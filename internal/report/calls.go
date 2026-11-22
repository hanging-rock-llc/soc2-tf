package report

import (
	"encoding/csv"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/hanging-rock-llc/soc2-tf/internal/cloudtrail"
)

// CallSource looks up the AWS API calls of role sessions
// (*cloudtrail.Source satisfies it).
type CallSource interface {
	Lookup(qs []cloudtrail.Query) ([][]cloudtrail.Event, error)
}

// JoinCloudTrail attaches to each apply the AWS API calls its role session
// made in the lookback window before the apply was recorded. The session
// name ties the calls to one CI run (role-session-name gha-<run>-<attempt>),
// so lookback only needs to cover the apply job's session lifetime.
func (res *Result) JoinCloudTrail(src CallSource, lookback time.Duration) error {
	var qs []cloudtrail.Query
	var rows []int
	for i, row := range res.Applies {
		id := row.Rec.CloudIdentity
		if id == nil || id.RoleSessionName == "" || id.Account == "" {
			continue
		}
		to := row.Rec.CapturedAt
		qs = append(qs, cloudtrail.Query{Account: id.Account, SessionARN: id.ARN, From: to.Add(-lookback), To: to})
		rows = append(rows, i)
	}
	found, err := src.Lookup(qs)
	if err != nil {
		return err
	}
	for qi, i := range rows {
		res.Applies[i].Calls = found[qi]
		res.Applies[i].CallsChecked = true
	}
	res.CloudTrail = true
	return nil
}

func callCounts(row Row) (calls, errs string) {
	if !row.CallsChecked {
		return "", ""
	}
	n := 0
	for _, e := range row.Calls {
		if e.ErrorCode != "" {
			n++
		}
	}
	return strconv.Itoa(len(row.Calls)), strconv.Itoa(n)
}

var callsHeader = []string{
	"record_id", "role_session_arn", "event_time", "event_source", "event_name", "aws_region",
	"read_only", "error_code", "error_message", "resources", "event_id",
}

// WriteAPICalls writes every AWS API call made by each apply's role session.
func (res *Result) WriteAPICalls(w io.Writer) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(callsHeader); err != nil {
		return err
	}
	for _, row := range res.Applies {
		for _, e := range row.Calls {
			if err := cw.Write([]string{
				row.Rec.ID, row.Rec.CloudIdentity.ARN, e.Time.UTC().Format(time.RFC3339), e.Source, e.Name, e.Region,
				strconv.FormatBool(e.ReadOnly), e.ErrorCode, e.ErrorMessage, strings.Join(e.Resources, " "), e.EventID,
			}); err != nil {
				return err
			}
		}
	}
	cw.Flush()
	return cw.Error()
}
