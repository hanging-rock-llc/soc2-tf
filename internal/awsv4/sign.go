// Package awsv4 implements AWS Signature Version 4 request signing using only
// the Go standard library. tfproof deliberately has no third-party
// dependencies so that the code that produces audit evidence is small enough
// to review in an afternoon.
package awsv4

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// Credentials are static or temporary AWS credentials.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// ErrNoCredentials is returned when no credentials are present in the
// environment.
var ErrNoCredentials = errors.New("no AWS credentials in environment (set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, e.g. via aws-actions/configure-aws-credentials)")

// FromEnv reads credentials from the standard AWS environment variables. This
// is what aws-actions/configure-aws-credentials exports after an OIDC role
// assumption, and what `aws configure export-credentials --format env`
// produces locally.
func FromEnv() (Credentials, error) {
	c := Credentials{
		AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
		SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
	}
	if c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return Credentials{}, ErrNoCredentials
	}
	return c, nil
}

// Region returns the region from AWS_REGION or AWS_DEFAULT_REGION.
func Region() string {
	if r := os.Getenv("AWS_REGION"); r != "" {
		return r
	}
	return os.Getenv("AWS_DEFAULT_REGION")
}

// HashHex returns the lowercase hex SHA-256 of b.
func HashHex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

// URIEncode encodes s per the SigV4 rules: unreserved characters
// (A-Z a-z 0-9 - _ . ~) are left as-is, everything else is percent-encoded
// with uppercase hex. If encodeSlash is false, '/' is preserved.
func URIEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// CanonicalQuery encodes q in SigV4 canonical form (sorted, RFC 3986 encoded).
// Using it as the wire query string keeps the signed and sent forms identical.
func CanonicalQuery(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vals := append([]string(nil), q[k]...)
		sort.Strings(vals)
		for _, v := range vals {
			parts = append(parts, URIEncode(k, true)+"="+URIEncode(v, true))
		}
	}
	return strings.Join(parts, "&")
}

// Sign adds SigV4 authentication headers to req. payloadHash is the hex
// SHA-256 of the request body (use HashHex). The canonical URI is taken from
// req.URL.EscapedPath(); for S3 the caller must build the path with
// URIEncode(key, false) so it is not double-encoded.
//
// Headers signed: host, x-amz-date, x-amz-content-sha256 (if set),
// x-amz-security-token (if session token), plus any header in req.Header
// whose name starts with "x-amz-" or equals "content-type".
func Sign(req *http.Request, creds Credentials, region, service, payloadHash string, now time.Time) {
	t := now.UTC()
	amzDate := t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")

	req.Header.Set("X-Amz-Date", amzDate)
	if creds.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", creds.SessionToken)
	}
	host := req.URL.Host
	if req.Host != "" {
		host = req.Host
	}

	headers := map[string]string{"host": host}
	for k, v := range req.Header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-amz-") || lk == "content-type" || lk == "content-md5" {
			headers[lk] = strings.Join(trimAll(v), ",")
		}
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var ch strings.Builder
	for _, n := range names {
		ch.WriteString(n + ":" + headers[n] + "\n")
	}
	signedHeaders := strings.Join(names, ";")

	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	canonicalRequest := strings.Join([]string{
		req.Method,
		path,
		CanonicalQuery(req.URL.Query()),
		ch.String(),
		signedHeaders,
		payloadHash,
	}, "\n")

	scope := dateStamp + "/" + region + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		HashHex([]byte(canonicalRequest)),
	}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+creds.SecretAccessKey), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		creds.AccessKeyID, scope, signedHeaders, sig))
}

func trimAll(v []string) []string {
	out := make([]string, len(v))
	for i, s := range v {
		out[i] = strings.Join(strings.Fields(s), " ")
	}
	return out
}
