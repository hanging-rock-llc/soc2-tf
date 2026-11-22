package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/hanging-rock-llc/soc2-tf/internal/record"
)

// fakeS3 is a path-style S3 stand-in that enforces the things tfproof relies
// on: signed requests, sha256 checksums on PUT, and paginated listing.
type fakeS3 struct {
	mu      sync.Mutex
	objects map[string][]byte
	puts    int
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIATEST/") {
		http.Error(w, "unsigned", http.StatusForbidden)
		return
	}
	// path: /<bucket>/<key...>
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
	key := ""
	if len(parts) == 2 {
		key = parts[1]
	}
	switch r.Method {
	case http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		sum := sha256.Sum256(body)
		if r.Header.Get("X-Amz-Checksum-Sha256") != base64.StdEncoding.EncodeToString(sum[:]) {
			http.Error(w, "BadDigest", http.StatusBadRequest)
			return
		}
		f.objects[key] = body
		f.puts++
	case http.MethodGet:
		if r.URL.Query().Get("list-type") == "2" {
			prefix := r.URL.Query().Get("prefix")
			var keys []string
			for k := range f.objects {
				if strings.HasPrefix(k, prefix) {
					keys = append(keys, k)
				}
			}
			sort.Strings(keys)
			start := 0
			if tok := r.URL.Query().Get("continuation-token"); tok != "" {
				fmt.Sscanf(tok, "%d", &start)
			}
			end := start + 3 // small pages to exercise pagination
			truncated := end < len(keys)
			if end > len(keys) {
				end = len(keys)
			}
			fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult>`)
			for _, k := range keys[start:end] {
				fmt.Fprintf(w, "<Contents><Key>%s</Key></Contents>", k)
			}
			if truncated {
				fmt.Fprintf(w, "<IsTruncated>true</IsTruncated><NextContinuationToken>%d</NextContinuationToken>", end)
			} else {
				fmt.Fprint(w, "<IsTruncated>false</IsTruncated>")
			}
			fmt.Fprint(w, "</ListBucketResult>")
			return
		}
		b, ok := f.objects[key]
		if !ok {
			http.Error(w, "NoSuchKey", http.StatusNotFound)
			return
		}
		w.Write(b)
	default:
		http.Error(w, "method", http.StatusMethodNotAllowed)
	}
}

func fakeGitHub(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/acme/infra/pulls/7", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"number":7,"html_url":"https://github.com/acme/infra/pull/7","title":"Add logs bucket",
			"user":{"login":"alice"},"head":{"sha":"headsha"},"base":{"ref":"main"},
			"merged":true,"merge_commit_sha":"mergesha","merged_by":{"login":"bob"}}`)
	})
	mux.HandleFunc("/repos/acme/infra/pulls/7/reviews", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[
			{"user":{"login":"bob"},"state":"CHANGES_REQUESTED","commit_id":"oldsha","submitted_at":"2026-11-20T10:00:00Z"},
			{"user":{"login":"bob"},"state":"APPROVED","commit_id":"headsha","submitted_at":"2026-11-20T12:00:00Z"},
			{"user":{"login":"carol"},"state":"COMMENTED","commit_id":"headsha","submitted_at":"2026-11-20T13:00:00Z"}
		]`)
	})
	mux.HandleFunc("/repos/acme/infra/commits/mergesha/pulls", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[{"number":7,"merged_at":"2026-11-20T14:00:00Z"}]`)
	})
	mux.HandleFunc("/repos/acme/infra/actions/runs/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/approvals") {
			fmt.Fprint(w, `[{"state":"approved","comment":"lgtm","environments":[{"name":"production"}],"user":{"login":"dave"}}]`)
			return
		}
		http.NotFound(w, r)
	})
	return httptest.NewServer(mux)
}

func fakeSTS() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<GetCallerIdentityResponse><GetCallerIdentityResult>
			<Arn>arn:aws:sts::123456789012:assumed-role/tf-apply/gha-555-1</Arn>
			<UserId>AROA:gha-555-1</UserId><Account>123456789012</Account>
			</GetCallerIdentityResult></GetCallerIdentityResponse>`)
	}))
}

const planA = `{"format_version":"1.2","terraform_version":"1.10.5","resource_changes":[
 {"address":"aws_s3_bucket.logs","change":{"actions":["create"]}},
 {"address":"aws_iam_role.ci","change":{"actions":["update"]}}]}`

const planEvil = `{"format_version":"1.2","terraform_version":"1.10.5","resource_changes":[
 {"address":"aws_s3_bucket.logs","change":{"actions":["create"]}},
 {"address":"aws_iam_role.ci","change":{"actions":["delete"]}}]}`

func setRun(t *testing.T, dir, runID, event, sha, eventJSON string) {
	t.Helper()
	ev := filepath.Join(dir, "event-"+runID+".json")
	os.WriteFile(ev, []byte(eventJSON), 0o644)
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_REPOSITORY", "acme/infra")
	t.Setenv("GITHUB_RUN_ID", runID)
	t.Setenv("GITHUB_RUN_ATTEMPT", "1")
	t.Setenv("GITHUB_EVENT_NAME", event)
	t.Setenv("GITHUB_EVENT_PATH", ev)
	t.Setenv("GITHUB_SHA", sha)
	t.Setenv("GITHUB_ACTOR", "bob")
	t.Setenv("GITHUB_WORKSPACE", dir)
	t.Setenv("GITHUB_OUTPUT", filepath.Join(dir, "out-"+runID))
	t.Setenv("GITHUB_STEP_SUMMARY", filepath.Join(dir, "summary-"+runID+".md"))
}

func TestEndToEnd(t *testing.T) {
	dir := t.TempDir()
	s3 := &fakeS3{objects: map[string][]byte{}}
	s3srv := httptest.NewServer(s3)
	defer s3srv.Close()
	gh := fakeGitHub(t)
	defer gh.Close()
	sts := fakeSTS()
	defer sts.Close()

	t.Setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	t.Setenv("AWS_SESSION_TOKEN", "session")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("TFPROOF_S3_ENDPOINT", s3srv.URL)
	t.Setenv("TFPROOF_STS_ENDPOINT", sts.URL)
	t.Setenv("GITHUB_API_URL", gh.URL)
	t.Setenv("GITHUB_TOKEN", "ghs_test")
	t.Setenv("TFPROOF_SINK", "s3://evidence-bucket/tfproof")

	wd := filepath.Join(dir, "infra", "prod")
	os.MkdirAll(wd, 0o755)
	os.WriteFile(filepath.Join(wd, "plan.json"), []byte(planA), 0o644)
	os.WriteFile(filepath.Join(wd, "evil.json"), []byte(planEvil), 0o644)
	os.WriteFile(filepath.Join(wd, "tfplan"), []byte("binary-plan-A"), 0o644)
	os.WriteFile(filepath.Join(wd, "tfplan-other"), []byte("binary-plan-B"), 0o644)
	os.WriteFile(filepath.Join(wd, "apply.log"), []byte("Apply complete! Resources: 1 added, 1 changed, 0 destroyed."), 0o644)

	// 1. Plan on the pull request.
	setRun(t, dir, "444", "pull_request", "headsha", `{"pull_request":{"number":7}}`)
	if err := run([]string{"capture", "plan", "--workdir", wd, "--plan-json", "plan.json"}); err != nil {
		t.Fatalf("capture plan (PR): %v", err)
	}
	if _, ok := s3.objects["tfproof/index/acme/infra/pr/7/infra__prod/plan.json"]; !ok {
		t.Fatalf("PR index not written; objects: %v", keys(s3.objects))
	}
	summary, _ := os.ReadFile(filepath.Join(dir, "summary-444.md"))
	if !strings.Contains(string(summary), "aws_s3_bucket.logs") {
		t.Fatalf("step summary missing change list:\n%s", summary)
	}

	// 2. Merge -> push run: plan job, then gated apply job (same run).
	setRun(t, dir, "555", "push", "mergesha", `{"ref":"refs/heads/main"}`)
	if err := run([]string{"capture", "plan", "--workdir", wd, "--plan-json", "plan.json", "--plan-file", "tfplan"}); err != nil {
		t.Fatalf("capture plan (push): %v", err)
	}
	if err := run([]string{"verify", "--workdir", wd, "--plan-json", "plan.json", "--plan-file", "tfplan", "--require-same-run", "--require-pr"}); err != nil {
		t.Fatalf("verify should pass: %v", err)
	}
	// A different plan file must fail the gate with exit code 2.
	err := run([]string{"verify", "--workdir", wd, "--plan-json", "plan.json", "--plan-file", "tfplan-other", "--require-same-run"})
	if ee, ok := err.(exitError); !ok || ee.code != 2 {
		t.Fatalf("verify with swapped plan file should exit 2, got %v", err)
	}
	// A plan that differs from what was reviewed on the PR must fail too.
	err = run([]string{"verify", "--workdir", wd, "--plan-json", "evil.json", "--require-pr"})
	if ee, ok := err.(exitError); !ok || ee.code != 2 {
		t.Fatalf("verify with changed change set should exit 2, got %v", err)
	}

	if err := run([]string{"capture", "apply", "--workdir", wd, "--plan-json", "plan.json", "--plan-file", "tfplan",
		"--exit-code", "0", "--log", filepath.Join(wd, "apply.log")}); err != nil {
		t.Fatalf("capture apply: %v", err)
	}

	// Find and inspect the apply record.
	var applyRec *record.Record
	for k, v := range s3.objects {
		if strings.HasPrefix(k, "tfproof/records/") && strings.Contains(k, "-apply-") {
			r, ok, err := record.VerifyContent(v)
			if err != nil || !ok {
				t.Fatalf("apply record content check failed: ok=%v err=%v", ok, err)
			}
			applyRec = r
		}
	}
	if applyRec == nil {
		t.Fatalf("no apply record; objects: %v", keys(s3.objects))
	}
	a := applyRec.Approval
	if a == nil || strings.Join(a.ApprovedBy, ",") != "bob" || strings.Join(a.EnvironmentApprovedBy, ",") != "dave" || !a.IndependentApprover || !a.ApprovedHead {
		b, _ := json.MarshalIndent(applyRec.Approval, "", " ")
		t.Fatalf("unexpected approval evidence: %s", b)
	}
	v := applyRec.Apply.Verification
	if v == nil || !v.Passed || v.SameRun == nil || !*v.SameRun || v.PullRequest == nil || !*v.PullRequest {
		b, _ := json.MarshalIndent(v, "", " ")
		t.Fatalf("unexpected verification: %s", b)
	}
	if applyRec.CloudIdentity == nil || applyRec.CloudIdentity.RoleSessionName != "gha-555-1" {
		t.Fatalf("role session not captured: %+v", applyRec.CloudIdentity)
	}
	if applyRec.PullRequest == nil || applyRec.PullRequest.Author != "alice" {
		t.Fatalf("PR not resolved from merge commit: %+v", applyRec.PullRequest)
	}
	if applyRec.Apply.LogSHA256 == "" || applyRec.Apply.LogKey != "" {
		t.Fatalf("log should be hashed but not uploaded by default: %+v", applyRec.Apply)
	}

	// 3. A second apply with an unreviewed change set -> must show up as an exception.
	setRun(t, dir, "666", "workflow_dispatch", "othersha", `{}`)
	if err := run([]string{"capture", "apply", "--workdir", wd, "--plan-json", "evil.json", "--exit-code", "1", "--pr", "none"}); err != nil {
		t.Fatalf("capture apply (dispatch): %v", err)
	}

	// 4. Report.
	out := filepath.Join(dir, "evidence")
	if err := run([]string{"report", "--repo", "acme/infra", "--since", "2000-01-01", "--out-dir", out}); err != nil {
		t.Fatalf("report: %v", err)
	}
	f, _ := os.Open(filepath.Join(out, "changes.csv"))
	rows, err := csv.NewReader(f).ReadAll()
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected header + 2 applies, got %d rows", len(rows))
	}
	exCol := len(rows[0]) - 1
	if rows[1][exCol] != "" {
		t.Fatalf("first apply should have no exceptions, got %q", rows[1][exCol])
	}
	if !strings.Contains(rows[2][exCol], "not verified") && !strings.Contains(rows[2][exCol], "did not match") {
		t.Fatalf("second apply should be flagged, got %q", rows[2][exCol])
	}
	md, _ := os.ReadFile(filepath.Join(out, "summary.md"))
	if !strings.Contains(string(md), "Applies with exceptions: **1**") {
		t.Fatalf("summary missing exception count:\n%s", md)
	}

	// 5. Tampering with a stored record is detected.
	for k, v := range s3.objects {
		if strings.HasPrefix(k, "tfproof/records/") && strings.Contains(k, "555-1") && strings.Contains(k, "-apply-") {
			s3.objects[k] = []byte(strings.Replace(string(v), `"exit_code": 0`, `"exit_code": 0 `, 1))
			s3.objects[k] = []byte(strings.Replace(string(s3.objects[k]), `"bob"`, `"mallory"`, 1))
		}
	}
	if err := run([]string{"report", "--repo", "acme/infra", "--since", "2000-01-01", "--out-dir", out}); err != nil {
		t.Fatal(err)
	}
	md, _ = os.ReadFile(filepath.Join(out, "summary.md"))
	if !strings.Contains(string(md), "content hash mismatch") {
		t.Fatalf("tampered record not flagged:\n%s", md)
	}
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
