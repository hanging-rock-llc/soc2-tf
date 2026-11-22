// Package s3 is a minimal S3 client (PutObject, GetObject, ListObjectsV2)
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

// ErrNotFound is returned by Get when the key does not exist.
var ErrNotFound = errors.New("s3: object not found")

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

func (c *Client) do(method string, u *url.URL, body []byte, hdr http.Header) (*http.Response, error) {
	req, err := http.NewRequest(method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	payloadHash := awsv4.HashHex(body)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	awsv4.Sign(req, c.Creds, c.Region, "s3", payloadHash, now())
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	return hc.Do(req)
}

// PutOptions controls optional per-object settings.
type PutOptions struct {
	ContentType string
	// RetainUntil, when non-zero, sets an explicit Object Lock retention on the
	// object in addition to the bucket default.
	RetainUntil time.Time
	LockMode    string // GOVERNANCE or COMPLIANCE; default COMPLIANCE when RetainUntil set
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
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("s3 put %s: %s: %s", key, resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

// Get downloads key.
func (c *Client) Get(key string) ([]byte, error) {
	resp, err := c.do(http.MethodGet, c.objectURL(key, nil), nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("s3 get %s: %s: %s", key, resp.Status, strings.TrimSpace(string(b)))
	}
	return b, nil
}

type listResult struct {
	Contents []struct {
		Key string `xml:"Key"`
	} `xml:"Contents"`
	IsTruncated           bool   `xml:"IsTruncated"`
	NextContinuationToken string `xml:"NextContinuationToken"`
}

// List returns all keys under prefix (paginating as needed).
func (c *Client) List(prefix string) ([]string, error) {
	var keys []string
	token := ""
	for {
		q := url.Values{}
		q.Set("list-type", "2")
		q.Set("prefix", prefix)
		if token != "" {
			q.Set("continuation-token", token)
		}
		u := c.objectURL("", q)
		resp, err := c.do(http.MethodGet, u, nil, nil)
		if err != nil {
			return nil, err
		}
		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode/100 != 2 {
			return nil, fmt.Errorf("s3 list %s: %s: %s", prefix, resp.Status, strings.TrimSpace(string(b)))
		}
		var lr listResult
		if err := xml.Unmarshal(b, &lr); err != nil {
			return nil, fmt.Errorf("s3 list: parse: %w", err)
		}
		for _, o := range lr.Contents {
			keys = append(keys, o.Key)
		}
		if !lr.IsTruncated || lr.NextContinuationToken == "" {
			return keys, nil
		}
		token = lr.NextContinuationToken
	}
}
