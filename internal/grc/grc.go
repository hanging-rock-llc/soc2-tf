// Package grc pushes tfproof's apply evidence (changes.csv, summary.md) to a
// team's GRC (governance, risk & compliance) platform — Vanta or Drata — so
// an auditor can see current evidence without being handed S3 access.
package grc

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
)

// File is one piece of evidence content to upload — e.g. the changes.csv or
// summary.md that `tfproof report` writes.
type File struct {
	Name        string
	ContentType string
	Data        []byte
}

// multipartField is one part of a multipart/form-data body. Fields with a
// Filename are sent as file parts (Content-Disposition with filename, plus
// a Content-Type if set); fields without one are sent as plain form fields.
type multipartField struct {
	Name, Filename, ContentType string
	Value                       []byte
}

// encodeMultipart serializes fields into a multipart/form-data body in the
// given order, returning the body and the Content-Type header (including the
// generated boundary) to send alongside it.
func encodeMultipart(fields ...multipartField) ([]byte, string, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for _, f := range fields {
		var part io.Writer
		var err error
		if f.Filename != "" {
			h := make(textproto.MIMEHeader)
			h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, escapeQuotes(f.Name), escapeQuotes(f.Filename)))
			if f.ContentType != "" {
				h.Set("Content-Type", f.ContentType)
			}
			part, err = w.CreatePart(h)
		} else {
			part, err = w.CreateFormField(f.Name)
		}
		if err != nil {
			return nil, "", fmt.Errorf("multipart field %q: %w", f.Name, err)
		}
		if _, err := part.Write(f.Value); err != nil {
			return nil, "", fmt.Errorf("multipart field %q: %w", f.Name, err)
		}
	}
	if err := w.Close(); err != nil {
		return nil, "", fmt.Errorf("closing multipart body: %w", err)
	}
	return buf.Bytes(), w.FormDataContentType(), nil
}

var quoteEscaper = strings.NewReplacer("\\", "\\\\", `"`, "\\\"")

// escapeQuotes matches the private helper mime/multipart uses for
// Content-Disposition parameters, so filenames with quotes or backslashes
// don't break the header.
func escapeQuotes(s string) string {
	return quoteEscaper.Replace(s)
}

// maxErrorBody caps how much of a failed response body an error message
// quotes, so a misbehaving endpoint can't blow up logs with an HTML error
// page.
const maxErrorBody = 4 << 10

// readErrorBody reads and trims up to maxErrorBody bytes of resp.Body for
// inclusion in an error message. It only ever echoes what the server sent
// back, never request headers or credentials.
func readErrorBody(resp *http.Response) string {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	return strings.TrimSpace(string(b))
}
