package grc

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hanging-rock-llc/soc2-tf/internal/httpretry"
)

// noRetrySleep makes httpretry's backoff instant so tests that exercise a
// retry path (5xx responses) don't actually sleep.
func noRetrySleep(t *testing.T) {
	t.Helper()
	orig := httpretry.Sleep
	httpretry.Sleep = func(time.Duration) {}
	t.Cleanup(func() { httpretry.Sleep = orig })
}

// callLog records the method+path of every request a fake server saw, in
// order, so tests can assert on call ordering (e.g. upload before submit).
type callLog struct {
	mu    sync.Mutex
	calls []string
}

func (c *callLog) record(r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, r.Method+" "+r.URL.Path)
}

func (c *callLog) indexOf(substr string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, call := range c.calls {
		if strings.Contains(call, substr) {
			return i
		}
	}
	return -1
}

var testFiles = []File{
	{Name: "changes.csv", ContentType: "text/csv", Data: []byte("id,action\n1,apply\n")},
	{Name: "summary.md", ContentType: "text/markdown", Data: []byte("# Summary\n")},
}

func TestVantaPublishUploadsEachFileThenSubmitsOnce(t *testing.T) {
	noRetrySleep(t)
	var log callLog
	var tokenBody struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		Scope        string `json:"scope"`
		GrantType    string `json:"grant_type"`
	}
	var uploadedFilenames []string
	var uploadedDescriptions []string
	var sawBearer []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/oauth/token":
			if ct := r.Header.Get("Content-Type"); ct != "application/json" {
				t.Errorf("token request Content-Type = %q, want application/json", ct)
			}
			if err := json.NewDecoder(r.Body).Decode(&tokenBody); err != nil {
				t.Fatalf("decoding token request body: %v", err)
			}
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "vat_test123",
				"expires_in":   3600,
				"token_type":   "Bearer",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/documents/doc123/uploads":
			sawBearer = append(sawBearer, r.Header.Get("Authorization"))
			if err := r.ParseMultipartForm(1 << 20); err != nil {
				t.Fatalf("parsing multipart upload: %v", err)
			}
			fh := r.MultipartForm.File["file"][0]
			uploadedFilenames = append(uploadedFilenames, fh.Filename)
			uploadedDescriptions = append(uploadedDescriptions, r.FormValue("description"))
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{
				"id": "upload1", "fileName": fh.Filename, "title": "Manual Evidence",
				"description": r.FormValue("description"), "mimeType": fh.Header.Get("Content-Type"),
				"url": "https://app.vanta.com/doc", "uploadedByUserId": nil,
				"creationDate": "2024-07-30T18:50:39.419Z", "updatedDate": "2024-07-30T18:50:39.419Z",
				"deletionDate": nil, "effectiveDate": "2024-07-30T18:50:39.419Z",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/documents/doc123/submit":
			sawBearer = append(sawBearer, r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	v := &Vanta{BaseURL: srv.URL, ClientID: "cid", ClientSecret: "csecret", HTTP: srv.Client()}
	if err := v.Publish("doc123", "Q3 evidence", testFiles); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	if tokenBody.ClientID != "cid" || tokenBody.ClientSecret != "csecret" || tokenBody.GrantType != "client_credentials" {
		t.Errorf("token request body = %+v", tokenBody)
	}
	if tokenBody.Scope != vantaScope {
		t.Errorf("token request scope = %q, want %q", tokenBody.Scope, vantaScope)
	}

	if len(uploadedFilenames) != 2 || uploadedFilenames[0] != "changes.csv" || uploadedFilenames[1] != "summary.md" {
		t.Errorf("uploaded filenames = %v", uploadedFilenames)
	}
	for _, d := range uploadedDescriptions {
		if d != "Q3 evidence" {
			t.Errorf("upload description = %q, want %q", d, "Q3 evidence")
		}
	}
	for _, b := range sawBearer {
		if b != "Bearer vat_test123" {
			t.Errorf("Authorization header = %q", b)
		}
	}

	// Both uploads must happen before the single submit call.
	submitIdx := log.indexOf("/submit")
	if submitIdx == -1 {
		t.Fatal("submit was never called")
	}
	for i, call := range log.calls {
		if strings.Contains(call, "/uploads") && i > submitIdx {
			t.Errorf("upload at position %d happened after submit at %d: %v", i, submitIdx, log.calls)
		}
	}
	uploadCount := 0
	for _, call := range log.calls {
		if strings.Contains(call, "/uploads") {
			uploadCount++
		}
	}
	if uploadCount != 2 {
		t.Errorf("got %d upload calls, want 2", uploadCount)
	}
}

func TestVantaPublishUploadErrorSurfacesStatusAndSkipsSubmit(t *testing.T) {
	noRetrySleep(t)
	submitCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/oauth/token":
			json.NewEncoder(w).Encode(map[string]any{"access_token": "vat_test123"})
		case r.URL.Path == "/v1/documents/doc123/uploads":
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"error":"missing vanta-api.documents:upload scope"}`)
		case r.URL.Path == "/v1/documents/doc123/submit":
			submitCalled = true
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(srv.Close)

	v := &Vanta{BaseURL: srv.URL, ClientID: "cid", ClientSecret: "csecret", HTTP: srv.Client()}
	err := v.Publish("doc123", "desc", testFiles[:1])
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "vanta-api.documents:upload") {
		t.Errorf("error = %q, want it to mention 403 and the response body", err)
	}
	if submitCalled {
		t.Error("submit must not be called when an upload fails")
	}
}

func TestVantaTokenErrorSurfacesStatus(t *testing.T) {
	noRetrySleep(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"invalid_scope"}`)
	}))
	t.Cleanup(srv.Close)

	v := &Vanta{BaseURL: srv.URL, ClientID: "cid", ClientSecret: "wrong", HTTP: srv.Client()}
	err := v.Publish("doc123", "desc", testFiles)
	if err == nil || !strings.Contains(err.Error(), "400") || !strings.Contains(err.Error(), "invalid_scope") {
		t.Fatalf("err = %v, want it to mention 400 and invalid_scope", err)
	}
}

func TestDrataPublishReplacesExistingArtifactAndAddsNew(t *testing.T) {
	noRetrySleep(t)
	var log callLog
	var fileKeys []string
	var updateBody struct {
		NewArtifacts []struct {
			ArtifactType string `json:"artifactType"`
			FileKey      string `json:"fileKey"`
			ArtifactName string `json:"artifactName"`
			FiledAt      string `json:"filedAt"`
		} `json:"newArtifacts"`
		ReplaceArtifacts []struct {
			ArtifactType       string `json:"artifactType"`
			FileKey            string `json:"fileKey"`
			ArtifactName       string `json:"artifactName"`
			FiledAt            string `json:"filedAt"`
			ExistingArtifactID int    `json:"existingArtifactId"`
		} `json:"replaceArtifacts"`
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.record(r)
		if auth := r.Header.Get("Authorization"); auth != "Bearer test-api-key" {
			t.Errorf("Authorization header = %q", auth)
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/workspaces/5/evidence-files":
			if err := r.ParseMultipartForm(1 << 20); err != nil {
				t.Fatalf("parsing multipart upload: %v", err)
			}
			fh := r.MultipartForm.File["file"][0]
			fileKeys = append(fileKeys, fh.Filename)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{
				"fileKey":          "acct/evidence-library/uuid/" + fh.Filename,
				"originalFilename": fh.Filename,
				"mimeType":         fh.Header.Get("Content-Type"),
				"fileSize":         len(testFiles[0].Data),
			})
		case r.Method == http.MethodGet && r.URL.Path == "/workspaces/5/evidence/9":
			if got := r.URL.Query()["expand[]"]; len(got) != 1 || got[0] != "artifacts" {
				t.Errorf("expand[] query = %v, want [artifacts]", got)
			}
			json.NewEncoder(w).Encode(map[string]any{
				"id": 9,
				"artifacts": map[string]any{
					"data": []map[string]any{
						{"id": 42, "artifactName": "changes.csv", "archivedAt": nil},
						{"id": 7, "artifactName": "old-report.pdf", "archivedAt": "2024-01-01T00:00:00.000Z"},
					},
				},
			})
		case r.Method == http.MethodPut && r.URL.Path == "/workspaces/5/evidence/9":
			if err := json.NewDecoder(r.Body).Decode(&updateBody); err != nil {
				t.Fatalf("decoding update body: %v", err)
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{"id": 9})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	d := &Drata{BaseURL: srv.URL, APIKey: "test-api-key", HTTP: srv.Client()}
	if err := d.Publish(5, 9, testFiles); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	if len(fileKeys) != 2 || fileKeys[0] != "changes.csv" || fileKeys[1] != "summary.md" {
		t.Fatalf("uploaded filenames = %v", fileKeys)
	}

	// changes.csv matches an existing current artifact -> replaceArtifacts.
	if len(updateBody.ReplaceArtifacts) != 1 {
		t.Fatalf("replaceArtifacts = %+v, want 1 entry", updateBody.ReplaceArtifacts)
	}
	r0 := updateBody.ReplaceArtifacts[0]
	if r0.ArtifactName != "changes.csv" || r0.ArtifactType != "S3_FILE" || r0.ExistingArtifactID != 42 ||
		!strings.Contains(r0.FileKey, "changes.csv") || r0.FiledAt == "" {
		t.Errorf("replaceArtifacts[0] = %+v", r0)
	}

	// summary.md has no current artifact match -> newArtifacts.
	if len(updateBody.NewArtifacts) != 1 {
		t.Fatalf("newArtifacts = %+v, want 1 entry", updateBody.NewArtifacts)
	}
	n0 := updateBody.NewArtifacts[0]
	if n0.ArtifactName != "summary.md" || n0.ArtifactType != "S3_FILE" || !strings.Contains(n0.FileKey, "summary.md") || n0.FiledAt == "" {
		t.Errorf("newArtifacts[0] = %+v", n0)
	}

	// Both uploads must precede the evidence update.
	putIdx := log.indexOf("PUT /workspaces/5/evidence/9")
	if putIdx == -1 {
		t.Fatal("PUT evidence was never called")
	}
	for i, call := range log.calls {
		if strings.Contains(call, "/evidence-files") && i > putIdx {
			t.Errorf("upload-file at position %d happened after PUT at %d: %v", i, putIdx, log.calls)
		}
	}
}

func TestDrataPublishUploadErrorSurfacesStatusAndSkipsUpdate(t *testing.T) {
	noRetrySleep(t)
	updateCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/workspaces/5/evidence-files":
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"message":"Unsupported file extension"}`)
		case r.URL.Path == "/workspaces/5/evidence/9":
			updateCalled = true
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{"id": 9})
		}
	}))
	t.Cleanup(srv.Close)

	d := &Drata{BaseURL: srv.URL, APIKey: "test-api-key", HTTP: srv.Client()}
	err := d.Publish(5, 9, testFiles[:1])
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "400") || !strings.Contains(err.Error(), "Unsupported file extension") {
		t.Errorf("error = %q, want it to mention 400 and the response body", err)
	}
	if updateCalled {
		t.Error("evidence update must not be called when a file upload fails")
	}
}

func TestEncodeMultipartRoundTrips(t *testing.T) {
	body, contentType, err := encodeMultipart(
		multipartField{Name: "file", Filename: `odd"name.csv`, ContentType: "text/csv", Value: []byte("a,b\n1,2\n")},
		multipartField{Name: "description", Value: []byte("hello world")},
	)
	if err != nil {
		t.Fatalf("encodeMultipart: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", contentType)
	if err := req.ParseMultipartForm(1 << 20); err != nil {
		t.Fatalf("ParseMultipartForm: %v", err)
	}
	fh := req.MultipartForm.File["file"][0]
	if fh.Filename != `odd"name.csv` {
		t.Errorf("filename = %q", fh.Filename)
	}
	f, err := fh.Open()
	if err != nil {
		t.Fatalf("opening file part: %v", err)
	}
	defer f.Close()
	data, _ := io.ReadAll(f)
	if string(data) != "a,b\n1,2\n" {
		t.Errorf("file content = %q", data)
	}
	if req.FormValue("description") != "hello world" {
		t.Errorf("description = %q", req.FormValue("description"))
	}
}

func TestDrataUploadResponseRequiresFileKey(t *testing.T) {
	noRetrySleep(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/workspaces/5/evidence-files":
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"originalFilename": "changes.csv"})
		}
	}))
	t.Cleanup(srv.Close)

	d := &Drata{BaseURL: srv.URL, APIKey: "k", HTTP: srv.Client()}
	err := d.Publish(5, 9, testFiles[:1])
	if err == nil || !strings.Contains(err.Error(), "fileKey") {
		t.Fatalf("err = %v, want it to mention the missing fileKey", err)
	}
}

func TestDrataRetriesTransientUploadFailure(t *testing.T) {
	noRetrySleep(t)
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/workspaces/5/evidence-files":
			attempts++
			if attempts == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			r.ParseMultipartForm(1 << 20)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"fileKey": "k1", "originalFilename": "changes.csv"})
		case "/workspaces/5/evidence/9":
			if r.Method == http.MethodGet {
				json.NewEncoder(w).Encode(map[string]any{"id": 9, "artifacts": map[string]any{"data": []any{}}})
				return
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{"id": 9})
		}
	}))
	t.Cleanup(srv.Close)

	d := &Drata{BaseURL: srv.URL, APIKey: "k", HTTP: srv.Client()}
	if err := d.Publish(5, 9, testFiles[:1]); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if attempts != 2 {
		t.Errorf("attempts = %d, want 2 (one transient failure then success)", attempts)
	}
}

// TestDrataFiledAtIsDateOnly checks the artifact's filedAt is a plain
// YYYY-MM-DD date, matching the docs' examples (e.g. "2020-07-06"), not a
// full RFC3339 timestamp.
func TestDrataFiledAtIsDateOnly(t *testing.T) {
	noRetrySleep(t)
	var filedAt string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/workspaces/5/evidence-files":
			r.ParseMultipartForm(1 << 20)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"fileKey": "k1", "originalFilename": "changes.csv"})
		case r.Method == http.MethodGet && r.URL.Path == "/workspaces/5/evidence/9":
			json.NewEncoder(w).Encode(map[string]any{"id": 9, "artifacts": map[string]any{"data": []any{}}})
		case r.Method == http.MethodPut && r.URL.Path == "/workspaces/5/evidence/9":
			var body struct {
				NewArtifacts []struct {
					FiledAt string `json:"filedAt"`
				} `json:"newArtifacts"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			if len(body.NewArtifacts) == 1 {
				filedAt = body.NewArtifacts[0].FiledAt
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{"id": 9})
		}
	}))
	t.Cleanup(srv.Close)

	d := &Drata{BaseURL: srv.URL, APIKey: "k", HTTP: srv.Client()}
	if err := d.Publish(5, 9, testFiles[:1]); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if _, err := time.Parse("2006-01-02", filedAt); err != nil {
		t.Errorf("filedAt = %q, want YYYY-MM-DD: %v", filedAt, err)
	}
}
