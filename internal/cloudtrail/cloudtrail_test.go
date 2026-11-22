package cloudtrail

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hanging-rock-llc/soc2-tf/internal/awsv4"
	"github.com/hanging-rock-llc/soc2-tf/internal/httpretry"
	"github.com/hanging-rock-llc/soc2-tf/internal/s3"
)

// fakeTrail is an in-memory CloudTrail-shaped S3 bucket: it serves
// ListObjectsV2 against exactly the prefixes registered with addListing and
// GetObject for keys registered with addFile, and records how each was used
// so tests can assert on fetch behavior.
type fakeTrail struct {
	mu           sync.Mutex
	listing      map[string][]string // list prefix -> keys
	listRequests []string            // every prefix a ListObjectsV2 call asked for
	objects      map[string][]byte   // key -> gzipped body
	gets         map[string]int      // key -> GetObject call count
}

func newFakeTrail() *fakeTrail {
	return &fakeTrail{
		listing: map[string][]string{},
		objects: map[string][]byte{},
		gets:    map[string]int{},
	}
}

func (f *fakeTrail) addListing(prefix string, keys []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listing[prefix] = keys
}

func (f *fakeTrail) addFile(key string, records []ctRecord) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if err := json.NewEncoder(gz).Encode(ctFile{Records: records}); err != nil {
		panic(err)
	}
	if err := gz.Close(); err != nil {
		panic(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[key] = buf.Bytes()
}

func (f *fakeTrail) getCount(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gets[key]
}

func (f *fakeTrail) listedPrefixes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.listRequests))
	copy(out, f.listRequests)
	return out
}

func (f *fakeTrail) handler(bucket string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("list-type") == "2" {
			prefix := r.URL.Query().Get("prefix")
			f.mu.Lock()
			f.listRequests = append(f.listRequests, prefix)
			keys := f.listing[prefix]
			f.mu.Unlock()
			var sb strings.Builder
			sb.WriteString("<ListBucketResult>")
			for _, k := range keys {
				fmt.Fprintf(&sb, "<Contents><Key>%s</Key></Contents>", k)
			}
			sb.WriteString("<IsTruncated>false</IsTruncated></ListBucketResult>")
			fmt.Fprint(w, sb.String())
			return
		}
		key := strings.TrimPrefix(r.URL.Path, "/"+bucket+"/")
		f.mu.Lock()
		body, ok := f.objects[key]
		if ok {
			f.gets[key]++
		}
		f.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `<Error><Code>NoSuchKey</Code></Error>`)
			return
		}
		w.Write(body)
	}
}

func testSource(t *testing.T, f *fakeTrail, regions ...string) *Source {
	t.Helper()
	srv := httptest.NewServer(f.handler("b"))
	t.Cleanup(srv.Close)
	orig := httpretry.Sleep
	httpretry.Sleep = func(time.Duration) {}
	t.Cleanup(func() { httpretry.Sleep = orig })
	client := &s3.Client{
		Bucket:   "b",
		Region:   "us-east-1",
		Creds:    awsv4.Credentials{AccessKeyID: "AK", SecretAccessKey: "s"},
		Endpoint: srv.URL,
	}
	return &Source{Client: client, Regions: regions}
}

const sessionARN = "arn:aws:sts::111122223333:assumed-role/ci-apply/run-42"

func TestLookupMatchesSessionAndWindow(t *testing.T) {
	f := newFakeTrail()
	s := testSource(t, f, "us-east-1")
	s.Prefix = "AWSLogs/{account}"

	dayPrefix := "AWSLogs/111122223333/CloudTrail/us-east-1/2024/01/15/"
	inWindowKey := dayPrefix + "111122223333_CloudTrail_us-east-1_20240115T1005Z_abc123.json.gz"
	outWindowKey := dayPrefix + "111122223333_CloudTrail_us-east-1_20240115T0950Z_def456.json.gz"
	f.addListing(dayPrefix, []string{inWindowKey, outWindowKey})

	f.addFile(inWindowKey, []ctRecord{
		{EventID: "e1", EventTime: "2024-01-15T10:03:00Z", EventSource: "ec2.amazonaws.com", EventName: "RunInstances", AWSRegion: "us-east-1", UserIdentity: struct {
			ARN string `json:"arn"`
		}{ARN: sessionARN}},
		{EventID: "e2", EventTime: "2024-01-15T10:04:00Z", EventSource: "ec2.amazonaws.com", EventName: "RunInstances", AWSRegion: "us-east-1", UserIdentity: struct {
			ARN string `json:"arn"`
		}{ARN: "arn:aws:sts::111122223333:assumed-role/other-role/other-session"}},
		{EventID: "e3", EventTime: "2024-01-15T09:00:00Z", EventSource: "ec2.amazonaws.com", EventName: "RunInstances", AWSRegion: "us-east-1", UserIdentity: struct {
			ARN string `json:"arn"`
		}{ARN: sessionARN}},
	})
	// Registered so a wrongful download would be detectable, but it must
	// never be fetched: its name timestamp is before the query window.
	f.addFile(outWindowKey, []ctRecord{
		{EventID: "e4", EventTime: "2024-01-15T09:52:00Z", EventSource: "ec2.amazonaws.com", EventName: "RunInstances", AWSRegion: "us-east-1", UserIdentity: struct {
			ARN string `json:"arn"`
		}{ARN: sessionARN}},
	})

	q := Query{
		Account:    "111122223333",
		SessionARN: sessionARN,
		From:       time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC),
		To:         time.Date(2024, 1, 15, 10, 10, 0, 0, time.UTC),
	}
	got, err := s.Lookup([]Query{q})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0]) != 1 || got[0][0].EventID != "e1" {
		t.Fatalf("Lookup = %+v", got)
	}
	if f.getCount(outWindowKey) != 0 {
		t.Fatalf("file outside window was downloaded: %d gets", f.getCount(outWindowKey))
	}
	if f.getCount(inWindowKey) != 1 {
		t.Fatalf("in-window file fetched %d times, want 1", f.getCount(inWindowKey))
	}
}

func TestLookupDownloadsSharedFileOnce(t *testing.T) {
	f := newFakeTrail()
	s := testSource(t, f, "us-east-1")
	s.Prefix = "AWSLogs/{account}"

	dayPrefix := "AWSLogs/111122223333/CloudTrail/us-east-1/2024/02/01/"
	key := dayPrefix + "111122223333_CloudTrail_us-east-1_20240201T1005Z_abc123.json.gz"
	f.addListing(dayPrefix, []string{key})

	arn2 := "arn:aws:sts::111122223333:assumed-role/ci-apply/run-99"
	f.addFile(key, []ctRecord{
		{EventID: "e1", EventTime: "2024-02-01T10:03:00Z", AWSRegion: "us-east-1", UserIdentity: struct {
			ARN string `json:"arn"`
		}{ARN: sessionARN}},
		{EventID: "e2", EventTime: "2024-02-01T10:04:00Z", AWSRegion: "us-east-1", UserIdentity: struct {
			ARN string `json:"arn"`
		}{ARN: arn2}},
	})

	qs := []Query{
		{Account: "111122223333", SessionARN: sessionARN,
			From: time.Date(2024, 2, 1, 10, 0, 0, 0, time.UTC), To: time.Date(2024, 2, 1, 10, 10, 0, 0, time.UTC)},
		{Account: "111122223333", SessionARN: arn2,
			From: time.Date(2024, 2, 1, 10, 0, 0, 0, time.UTC), To: time.Date(2024, 2, 1, 10, 10, 0, 0, time.UTC)},
	}
	got, err := s.Lookup(qs)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || len(got[0]) != 1 || got[0][0].EventID != "e1" || len(got[1]) != 1 || got[1][0].EventID != "e2" {
		t.Fatalf("Lookup = %+v", got)
	}
	if f.getCount(key) != 1 {
		t.Fatalf("shared file fetched %d times, want 1", f.getCount(key))
	}
}

func TestLookupSubstitutesAccountInPrefix(t *testing.T) {
	f := newFakeTrail()
	s := testSource(t, f, "us-east-1")
	s.Prefix = "logs/AWSLogs/o-abc123/{account}"

	dayPrefix := "logs/AWSLogs/o-abc123/222233334444/CloudTrail/us-east-1/2024/03/10/"
	key := dayPrefix + "222233334444_CloudTrail_us-east-1_20240310T1005Z_abc123.json.gz"
	f.addListing(dayPrefix, []string{key})
	f.addFile(key, []ctRecord{
		{EventID: "e1", EventTime: "2024-03-10T10:03:00Z", AWSRegion: "us-east-1", UserIdentity: struct {
			ARN string `json:"arn"`
		}{ARN: sessionARN}},
	})

	q := Query{
		Account:    "222233334444",
		SessionARN: sessionARN,
		From:       time.Date(2024, 3, 10, 10, 0, 0, 0, time.UTC),
		To:         time.Date(2024, 3, 10, 10, 10, 0, 0, time.UTC),
	}
	got, err := s.Lookup([]Query{q})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0]) != 1 || got[0][0].EventID != "e1" {
		t.Fatalf("Lookup with substituted account = %+v", got)
	}
}

func TestLookupListsBothDayPrefixesForMultiDayWindow(t *testing.T) {
	f := newFakeTrail()
	s := testSource(t, f, "us-east-1")
	s.Prefix = "AWSLogs/{account}"

	day14 := "AWSLogs/111122223333/CloudTrail/us-east-1/2024/01/14/"
	day15 := "AWSLogs/111122223333/CloudTrail/us-east-1/2024/01/15/"
	f.addListing(day14, nil)
	f.addListing(day15, nil)

	q := Query{
		Account:    "111122223333",
		SessionARN: sessionARN,
		// from - 5m falls on Jan 14; to + 20m stays on Jan 15.
		From: time.Date(2024, 1, 15, 0, 2, 0, 0, time.UTC),
		To:   time.Date(2024, 1, 15, 0, 5, 0, 0, time.UTC),
	}
	if _, err := s.Lookup([]Query{q}); err != nil {
		t.Fatal(err)
	}
	prefixes := f.listedPrefixes()
	has := func(p string) bool {
		for _, got := range prefixes {
			if got == p {
				return true
			}
		}
		return false
	}
	if !has(day14) || !has(day15) {
		t.Fatalf("expected both day prefixes listed, got %+v", prefixes)
	}
}
