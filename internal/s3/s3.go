// Package s3 is a minimal S3 client (PutObject, GetObject, ListObjectVersions)
// built on the standard library and the awsv4 signer.
package s3

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/hanging-rock-llc/soc2-tf/internal/awsv4"
	"github.com/hanging-rock-llc/soc2-tf/internal/httpretry"
)

// Client talks to a single bucket.
type Client struct {
	Bucket string
	Region string
	Creds  awsv4.Credentials
	// Endpoint overrides the S3 endpoint (path-style), e.g. for tests or
	// S3-compatible stores. Taken from TFPROOF_S3_ENDPOINT when empty.
	Endpoint string
	HTTP     *http.Client
	Now      func() time.Time
}

var (
	// ErrNotFound is returned by Get when the key does not exist.
	ErrNotFound = errors.New("s3: object not found")
	// ErrPreconditionFailed is returned by a create-only Put when the key
	// already exists.
	ErrPreconditionFailed = errors.New("s3: object already exists")
)

// New builds a client using environment credentials and region.
func New(bucket, region string) (*Client, error) {
	creds, err := awsv4.FromEnv()
	if err != nil {
		return nil, err
	}
	if region == "" {
		region = awsv4.Region()
	}
	if region == "" {
		return nil, errors.New("s3: no region (set AWS_REGION or --region)")
	}
	return &Client{
		Bucket:   bucket,
		Region:   region,
		Creds:    creds,
		Endpoint: os.Getenv("TFPROOF_S3_ENDPOINT"),
		HTTP:     &http.Client{Timeout: 60 * time.Second},
		Now:      time.Now,
	}, nil
}

func (c *Client) objectURL(key string, q url.Values) *url.URL {
	var u *url.URL
	escaped := awsv4.URIEncode(key, false)
	if c.Endpoint != "" {
		base := strings.TrimRight(c.Endpoint, "/")
		u, _ = url.Parse(base + "/" + c.Bucket + "/" + escaped)
	} else {
		u, _ = url.Parse(fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s", c.Bucket, c.Region, escaped))
	}
	// url.Parse decodes the path; force the exact escaped form for signing.
	if c.Endpoint != "" {
		u.RawPath = "/" + c.Bucket + "/" + escaped
	} else {
		u.RawPath = "/" + escaped
	}
	if q != nil {
		u.RawQuery = awsv4.CanonicalQuery(q)
	}
	return u
}

// do signs and sends a request, retrying transient failures. Each attempt is
// re-signed so the signature's timestamp stays fresh.
func (c *Client) do(method string, u *url.URL, body []byte, hdr http.Header) (*http.Response, error) {
	payloadHash := awsv4.HashHex(body)
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	return httpretry.Do(c.HTTP, func() (*http.Request, error) {
		req, err := http.NewRequest(method, u.String(), bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		for k, v := range hdr {
			req.Header[k] = v
		}
		req.Header.Set("X-Amz-Content-Sha256", payloadHash)
		awsv4.Sign(req, c.Creds, c.Region, "s3", payloadHash, now())
		return req, nil
	})
}

// PutOptions controls optional per-object settings.
type PutOptions struct {
	ContentType string
	// RetainUntil, when non-zero, sets an explicit Object Lock retention on the
	// object in addition to the bucket default.
	RetainUntil time.Time
	LockMode    string // GOVERNANCE or COMPLIANCE; default COMPLIANCE when RetainUntil set
	// IfNoneMatch makes the write create-only: S3 rejects it with 412 if the
	// key already has a current version.
	IfNoneMatch bool
}

// Put uploads body to key. It always sends an x-amz-checksum-sha256 so S3
// verifies integrity end to end (and so Object Lock uploads are accepted).
func (c *Client) Put(key string, body []byte, opt PutOptions) error {
	sum := sha256.Sum256(body)
	h := http.Header{}
	ct := opt.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	h.Set("Content-Type", ct)
	h.Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(sum[:]))
	if opt.IfNoneMatch {
		h.Set("If-None-Match", "*")
	}
	if !opt.RetainUntil.IsZero() {
		mode := opt.LockMode
		if mode == "" {
			mode = "COMPLIANCE"
		}
		h.Set("X-Amz-Object-Lock-Mode", mode)
		h.Set("X-Amz-Object-Lock-Retain-Until-Date", opt.RetainUntil.UTC().Format(time.RFC3339))
	}
	resp, err := c.do(http.MethodPut, c.objectURL(key, nil), body, h)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if opt.IfNoneMatch && resp.StatusCode == http.StatusPreconditionFailed {
		return ErrPreconditionFailed
	}
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("s3 put %s: %s: %s", key, resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

// Get downloads the current version of key. A missing key is ErrNotFound; a
// missing bucket is an error, not "not found".
func (c *Client) Get(key string) ([]byte, error) {
	resp, err := c.do(http.MethodGet, c.objectURL(key, nil), nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound && errorCode(b) != "NoSuchBucket" {
		return nil, ErrNotFound
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("s3 get %s: %s: %s", key, resp.Status, strings.TrimSpace(string(b)))
	}
	return b, nil
}

func errorCode(body []byte) string {
	var e struct {
		Code string `xml:"Code"`
	}
	if xml.Unmarshal(body, &e) != nil {
		return ""
	}
	return e.Code
}

// ObjectVersions summarizes the version history of one key.
type ObjectVersions struct {
	Key           string
	Versions      int  // object versions (excluding delete markers)
	DeleteMarkers int  // delete markers
	Deleted       bool // the current version is a delete marker
}

type versionsResult struct {
	Versions []struct {
		Key      string `xml:"Key"`
		IsLatest bool   `xml:"IsLatest"`
	} `xml:"Version"`
	DeleteMarkers []struct {
		Key      string `xml:"Key"`
		IsLatest bool   `xml:"IsLatest"`
	} `xml:"DeleteMarker"`
	IsTruncated         bool   `xml:"IsTruncated"`
	NextKeyMarker       string `xml:"NextKeyMarker"`
	NextVersionIDMarker string `xml:"NextVersionIdMarker"`
}

// ListVersions returns every key under prefix with its version counts, in key
// order (paginating as needed). Keys hidden by a delete marker are included.
func (c *Client) ListVersions(prefix string) ([]ObjectVersions, error) {
	var out []ObjectVersions
	idx := map[string]int{}
	entry := func(key string) *ObjectVersions {
		i, ok := idx[key]
		if !ok {
			i = len(out)
			idx[key] = i
			out = append(out, ObjectVersions{Key: key})
		}
		return &out[i]
	}
	keyMarker, versionMarker := "", ""
	for {
		q := url.Values{}
		q.Set("versions", "")
		q.Set("prefix", prefix)
		if keyMarker != "" {
			q.Set("key-marker", keyMarker)
			q.Set("version-id-marker", versionMarker)
		}
		resp, err := c.do(http.MethodGet, c.objectURL("", q), nil, nil)
		if err != nil {
			return nil, err
		}
		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode/100 != 2 {
			return nil, fmt.Errorf("s3 list versions %s: %s: %s", prefix, resp.Status, strings.TrimSpace(string(b)))
		}
		var lr versionsResult
		if err := xml.Unmarshal(b, &lr); err != nil {
			return nil, fmt.Errorf("s3 list versions: parse: %w", err)
		}
		for _, v := range lr.Versions {
			entry(v.Key).Versions++
		}
		for _, d := range lr.DeleteMarkers {
			e := entry(d.Key)
			e.DeleteMarkers++
			if d.IsLatest {
				e.Deleted = true
			}
		}
		if !lr.IsTruncated || lr.NextKeyMarker == "" {
			return out, nil
		}
		keyMarker, versionMarker = lr.NextKeyMarker, lr.NextVersionIDMarker
	}
}
