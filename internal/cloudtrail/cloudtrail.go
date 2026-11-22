// Package cloudtrail finds the AWS API calls a CI role session made, by
// reading the CloudTrail log files a trail delivers to S3.
package cloudtrail

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/hanging-rock-llc/soc2-tf/internal/s3"
)

// Event is one CloudTrail record, reduced to what an auditor needs.
type Event struct {
	Time         time.Time
	EventID      string
	Source       string // eventSource, e.g. s3.amazonaws.com
	Name         string // eventName
	Region       string // awsRegion
	ReadOnly     bool
	ErrorCode    string
	ErrorMessage string
	Resources    []string // resources[].ARN
}

// Query asks for events by one assumed-role session in a time window.
type Query struct {
	Account    string // 12-digit account ID that owns the log files
	SessionARN string // arn:aws:sts::<account>:assumed-role/<role>/<session>
	From, To   time.Time
}

// Source reads a trail's log files from S3.
type Source struct {
	Client  *s3.Client
	Prefix  string   // key prefix up to and including the account directory; "{account}" is replaced, e.g. "AWSLogs/{account}" or "logs/AWSLogs/o-abc123/{account}"
	Regions []string // regions whose logs to read
}

// deliveryDelay is the generous upper bound on how long after an event
// CloudTrail may still deliver the log file that contains it.
const deliveryDelay = 20 * time.Minute

// fileSpan is how far back a log file's name timestamp can reach for events
// it may contain; used only to decide which day prefixes to list.
const fileSpan = 5 * time.Minute

// ctRecord is one record of a CloudTrail log file, trimmed to the fields we
// need. Field names follow the documented CloudTrail record contract.
type ctRecord struct {
	EventID      string `json:"eventID"`
	EventTime    string `json:"eventTime"`
	EventSource  string `json:"eventSource"`
	EventName    string `json:"eventName"`
	AWSRegion    string `json:"awsRegion"`
	ReadOnly     bool   `json:"readOnly"`
	ErrorCode    string `json:"errorCode"`
	ErrorMessage string `json:"errorMessage"`
	UserIdentity struct {
		ARN string `json:"arn"`
	} `json:"userIdentity"`
	Resources []struct {
		ARN string `json:"ARN"`
	} `json:"resources"`
}

type ctFile struct {
	Records []ctRecord `json:"Records"`
}

// Lookup returns, for each query (by index), the matching events sorted by
// time. Each log file is downloaded at most once, however many queries need
// it.
func (s *Source) Lookup(qs []Query) ([][]Event, error) {
	out := make([][]Event, len(qs))
	seen := make([]map[string]bool, len(qs))
	for i := range qs {
		seen[i] = map[string]bool{}
	}

	type dayKey struct {
		account, region, day string // day is "YYYY/MM/DD"
	}
	listed := map[dayKey][]string{}

	// fileQueries maps a candidate log file key to the queries whose window
	// it might fall in, so each file is fetched once no matter how many
	// queries need it.
	fileQueries := map[string][]int{}

	for qi, q := range qs {
		from := q.From.UTC()
		to := q.To.UTC()
		windowEnd := to.Add(deliveryDelay)
		for d := startOfDay(from.Add(-fileSpan)); !d.After(startOfDay(windowEnd)); d = d.AddDate(0, 0, 1) {
			day := d.Format("2006/01/02")
			for _, region := range s.Regions {
				dk := dayKey{q.Account, region, day}
				keys, ok := listed[dk]
				if !ok {
					prefix := strings.ReplaceAll(s.Prefix, "{account}", q.Account) + "/CloudTrail/" + region + "/" + day + "/"
					ks, err := s.Client.List(prefix)
					if err != nil {
						return nil, fmt.Errorf("cloudtrail list %s: %w", prefix, err)
					}
					keys = ks
					listed[dk] = keys
				}
				for _, key := range keys {
					ts, ok := fileTimestamp(key)
					if !ok {
						continue
					}
					if ts.Before(from) || ts.After(windowEnd) {
						continue
					}
					fileQueries[key] = append(fileQueries[key], qi)
				}
			}
		}
	}

	for key, qis := range fileQueries {
		recs, err := s.loadFile(key)
		if err != nil {
			return nil, err
		}
		for _, qi := range qis {
			q := qs[qi]
			for _, r := range recs {
				if r.UserIdentity.ARN != q.SessionARN {
					continue
				}
				t, err := time.Parse(time.RFC3339, r.EventTime)
				if err != nil {
					continue
				}
				if t.Before(q.From) || t.After(q.To) {
					continue
				}
				if seen[qi][r.EventID] {
					continue
				}
				seen[qi][r.EventID] = true
				var resources []string
				for _, res := range r.Resources {
					resources = append(resources, res.ARN)
				}
				out[qi] = append(out[qi], Event{
					Time:         t,
					EventID:      r.EventID,
					Source:       r.EventSource,
					Name:         r.EventName,
					Region:       r.AWSRegion,
					ReadOnly:     r.ReadOnly,
					ErrorCode:    r.ErrorCode,
					ErrorMessage: r.ErrorMessage,
					Resources:    resources,
				})
			}
		}
	}

	for qi := range out {
		sort.Slice(out[qi], func(i, j int) bool { return out[qi][i].Time.Before(out[qi][j].Time) })
	}
	return out, nil
}

// loadFile downloads, gunzips and parses one log file. The caller discards
// the returned records once it has pulled out the events it needs.
func (s *Source) loadFile(key string) ([]ctRecord, error) {
	raw, err := s.Client.Get(key)
	if err != nil {
		return nil, fmt.Errorf("cloudtrail download %s: %w", key, err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("cloudtrail gunzip %s: %w", key, err)
	}
	defer gz.Close()
	var file ctFile
	if err := json.NewDecoder(gz).Decode(&file); err != nil {
		return nil, fmt.Errorf("cloudtrail parse %s: %w", key, err)
	}
	return file.Records, nil
}

// fileTimestamp extracts the "written at" timestamp embedded in a CloudTrail
// log file name: <account>_CloudTrail_<region>_<YYYYMMDDTHHmmZ>_<random>.json.gz.
// It reports false for digest files and anything that doesn't match.
func fileTimestamp(key string) (time.Time, bool) {
	if strings.Contains(key, "/CloudTrail-Digest/") {
		return time.Time{}, false
	}
	base := key
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	if !strings.HasSuffix(base, ".json.gz") {
		return time.Time{}, false
	}
	parts := strings.Split(base, "_")
	if len(parts) != 5 {
		return time.Time{}, false
	}
	t, err := time.Parse("20060102T1504Z", parts[3])
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func startOfDay(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}
