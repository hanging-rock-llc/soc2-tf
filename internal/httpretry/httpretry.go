// Package httpretry retries idempotent HTTP calls to AWS and GitHub. A capture
// that fails on a transient error loses evidence, so every request tfproof
// makes goes through here.
package httpretry

import (
	"io"
	"net/http"
	"strconv"
	"time"
)

// Attempts is the total number of tries per request.
const Attempts = 4

// Sleep waits between attempts; tests replace it.
var Sleep = time.Sleep

// Do sends the request built by newReq, retrying transport errors, 429 and 5xx
// responses with exponential backoff (0.5s, 1s, 2s) or the server's
// Retry-After (capped at 10s). newReq is called once per attempt so each try
// carries a fresh body and signature. The last response is returned as-is.
func Do(hc *http.Client, newReq func() (*http.Request, error)) (*http.Response, error) {
	if hc == nil {
		hc = http.DefaultClient
	}
	backoff := 500 * time.Millisecond
	for attempt := 1; ; attempt++ {
		req, err := newReq()
		if err != nil {
			return nil, err
		}
		resp, err := hc.Do(req)
		if attempt == Attempts || (err == nil && !retryable(resp.StatusCode)) {
			return resp, err
		}
		wait := backoff
		if err == nil {
			if s, perr := strconv.Atoi(resp.Header.Get("Retry-After")); perr == nil && s >= 0 {
				wait = min(time.Duration(s)*time.Second, 10*time.Second)
			}
			io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
		}
		Sleep(wait)
		backoff *= 2
	}
}

func retryable(code int) bool {
	return code == http.StatusTooManyRequests || code >= 500
}
