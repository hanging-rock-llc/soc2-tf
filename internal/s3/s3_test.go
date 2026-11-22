package s3

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hanging-rock-llc/soc2-tf/internal/awsv4"
	"github.com/hanging-rock-llc/soc2-tf/internal/httpretry"
)

func client(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	orig := httpretry.Sleep
	httpretry.Sleep = func(time.Duration) {}
	t.Cleanup(func() { httpretry.Sleep = orig })
	return &Client{Bucket: "b", Region: "us-east-1", Creds: awsv4.Credentials{AccessKeyID: "AK", SecretAccessKey: "s"}, Endpoint: srv.URL}
}

func TestPutCreateOnlyAndRetry(t *testing.T) {
	calls := 0
	c := client(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("If-None-Match") != "*" {
			t.Errorf("create-only put must send If-None-Match: *")
		}
		switch calls {
		case 1:
			w.WriteHeader(http.StatusServiceUnavailable) // transient: retried
		default:
			w.WriteHeader(http.StatusPreconditionFailed)
		}
	})
	err := c.Put("k", []byte("x"), PutOptions{IfNoneMatch: true})
	if !errors.Is(err, ErrPreconditionFailed) || calls != 2 {
		t.Fatalf("err=%v calls=%d; want ErrPreconditionFailed after one retry", err, calls)
	}
}

func TestGetDistinguishesMissingKeyFromMissingBucket(t *testing.T) {
	code := "NoSuchKey"
	c := client(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "<Error><Code>%s</Code></Error>", code)
	})
	if _, err := c.Get("k"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("NoSuchKey: %v", err)
	}
	code = "NoSuchBucket"
	if _, err := c.Get("k"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("NoSuchBucket must be an error, not 'not found': %v", err)
	}
}

func TestListVersionsCountsHistory(t *testing.T) {
	c := client(t, func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.URL.Query()["versions"]; !ok {
			t.Errorf("expected ?versions, got %s", r.URL.RawQuery)
		}
		if r.URL.Query().Get("key-marker") == "" {
			fmt.Fprint(w, `<ListVersionsResult><Version><Key>a</Key><IsLatest>true</IsLatest></Version>
				<Version><Key>a</Key><IsLatest>false</IsLatest></Version>
				<IsTruncated>true</IsTruncated><NextKeyMarker>a</NextKeyMarker><NextVersionIdMarker>v1</NextVersionIdMarker></ListVersionsResult>`)
			return
		}
		fmt.Fprint(w, `<ListVersionsResult><Version><Key>b</Key><IsLatest>false</IsLatest></Version>
			<DeleteMarker><Key>b</Key><IsLatest>true</IsLatest></DeleteMarker><IsTruncated>false</IsTruncated></ListVersionsResult>`)
	})
	got, err := c.ListVersions("")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != (ObjectVersions{Key: "a", Versions: 2}) || got[1] != (ObjectVersions{Key: "b", Versions: 1, DeleteMarkers: 1, Deleted: true}) {
		t.Fatalf("ListVersions = %+v", got)
	}
}

func TestListPaginates(t *testing.T) {
	var gotPrefixes []string
	c := client(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("list-type"); got != "2" {
			t.Errorf("expected list-type=2, got %q", got)
		}
		gotPrefixes = append(gotPrefixes, r.URL.Query().Get("prefix"))
		if r.URL.Query().Get("continuation-token") == "" {
			fmt.Fprint(w, `<ListBucketResult><Contents><Key>p/a</Key></Contents>
				<IsTruncated>true</IsTruncated><NextContinuationToken>tok1</NextContinuationToken></ListBucketResult>`)
			return
		}
		if r.URL.Query().Get("continuation-token") != "tok1" {
			t.Errorf("expected continuation-token=tok1, got %q", r.URL.Query().Get("continuation-token"))
		}
		fmt.Fprint(w, `<ListBucketResult><Contents><Key>p/b</Key></Contents><IsTruncated>false</IsTruncated></ListBucketResult>`)
	})
	got, err := c.List("p/")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "p/a" || got[1] != "p/b" {
		t.Fatalf("List = %+v", got)
	}
	if len(gotPrefixes) != 2 || gotPrefixes[0] != "p/" || gotPrefixes[1] != "p/" {
		t.Fatalf("prefix not sent on every page: %+v", gotPrefixes)
	}
}
