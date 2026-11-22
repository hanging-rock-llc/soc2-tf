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

// fakeS3 is a path-style, versioned S3 stand-in that enforces the things
// tfproof relies on: signed requests, sha256 checksums and If-None-Match on
// PUT, NoSuchKey errors, and paginated version listing.
type fakeS3 struct {
	mu      sync.Mutex
	objects map[string][][]byte // key -> versions, oldest first
	puts    int
}

func (f *fakeS3) current(key string) ([]byte, bool) {
	v := f.objects[key]
	if len(v) == 0 {
		return nil, false
	}
	return v[len(v)-1], true
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
		if _, exists := f.current(key); exists && r.Header.Get("If-None-Match") == "*" {
			http.Error(w, "PreconditionFailed", http.StatusPreconditionFailed)
			return
		}
		f.objects[key] = append(f.objects[key], body)
		f.puts++
	case http.MethodGet:
		if _, ok := r.URL.Query()["versions"]; ok {
			prefix := r.URL.Query().Get("prefix")
			var keys []string
			for k := range f.objects {
				if strings.HasPrefix(k, prefix) {
					keys = append(keys, k)
				}
			}
			sort.Strings(keys)
			start := 0
			if m := r.URL.Query().Get("key-marker"); m != "" {
				start = sort.SearchStrings(keys, m) + 1
			}
			end := start + 3 // small pages to exercise pagination
			truncated := end < len(keys)
			if end > len(keys) {
				end = len(keys)
			}
			fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><ListVersionsResult>`)
			for _, k := range keys[start:end] {
				for i := range f.objects[k] {
					fmt.Fprintf(w, "<Version><Key>%s</Key><VersionId>v%d</VersionId><IsLatest>%t</IsLatest></Version>", k, i, i == len(f.objects[k])-1)
				}
			}
			if truncated {
				fmt.Fprintf(w, "<IsTruncated>true</IsTruncated><NextKeyMarker>%s</NextKeyMarker><NextVersionIdMarker>x</NextVersionIdMarker>", keys[end-1])
			} else {
				fmt.Fprint(w, "<IsTruncated>false</IsTruncated>")
			}
			fmt.Fprint(w, "</ListVersionsResult>")
			return
		}
		b, ok := f.current(key)
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "<Error><Code>NoSuchKey</Code></Error>")
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
	mux.HandleFunc("/repos/acme/infra/pulls/7/commits", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[{"author":{"login":"alice"},"committer":{"login":"web-flow"}}]`)
	})
	mux.HandleFunc("/repos/acme/infra/commits/mergesha/pulls", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[{"number":7,"merged_at":"2026-11-20T14:00:00Z","merge_commit_sha":"mergesha"}]`)
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

// e2eEnv starts fake S3, STS and GitHub, points tfproof at them, and returns
// a workspace with plan fixtures in infra/prod.
func e2eEnv(t *testing.T) (dir, wd string, s3 *fakeS3) {
	t.Helper()
	dir = t.TempDir()
	s3 = &fakeS3{objects: map[string][][]byte{}}
	s3srv := httptest.NewServer(s3)
	t.Cleanup(s3srv.Close)
	gh := fakeGitHub(t)
	t.Cleanup(gh.Close)
	sts := fakeSTS()
	t.Cleanup(sts.Close)

	t.Setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	t.Setenv("AWS_SESSION_TOKEN", "session")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("TFPROOF_S3_ENDPOINT", s3srv.URL)
	t.Setenv("TFPROOF_STS_ENDPOINT", sts.URL)
	t.Setenv("GITHUB_API_URL", gh.URL)
	t.Setenv("GITHUB_TOKEN", "ghs_test")
	t.Setenv("TFPROOF_SINK", "s3://evidence-bucket/tfproof")
	t.Setenv("TF_WORKSPACE", "")

	wd = filepath.Join(dir, "infra", "prod")
	os.MkdirAll(wd, 0o755)
	os.WriteFile(filepath.Join(wd, "plan.json"), []byte(planA), 0o644)
	os.WriteFile(filepath.Join(wd, "evil.json"), []byte(planEvil), 0o644)
	os.WriteFile(filepath.Join(wd, "tfplan"), []byte("binary-plan-A"), 0o644)
	os.WriteFile(filepath.Join(wd, "tfplan-other"), []byte("binary-plan-B"), 0o644)
	os.WriteFile(filepath.Join(wd, "apply.log"), []byte("Apply complete! Resources: 1 added, 1 changed, 0 destroyed."), 0o644)
	return dir, wd, s3
}

const prEvent = `{"pull_request":{"number":7,"head":{"sha":"headsha"}}}`

func TestEndToEnd(t *testing.T) {
	dir, wd, s3 := e2eEnv(t)

	// 1. Plan on the pull request.
	setRun(t, dir, "444", "pull_request", "prmergeref", prEvent)
	if err := run([]string{"capture", "plan", "--workdir", wd, "--plan-json", "plan.json"}); err != nil {
		t.Fatalf("capture plan (PR): %v", err)
	}
	if _, ok := s3.current("tfproof/index/acme/infra/pr/7/infra__prod/plan.json"); !ok {
		t.Fatalf("PR index not written; objects: %v", keys(s3.objects))
	}
	summary, _ := os.ReadFile(filepath.Join(dir, "summary-444.md"))
	if !strings.Contains(string(summary), "aws_s3_bucket.logs") {
		t.Fatalf("step summary missing change list:\n%s", summary)
	}

	// 2. Merge -> push run: plan job, then gated apply job (same run).
	setRun(t, dir, "555", "push", "mergesha", `{"ref":"refs/heads/main"}`)
	t.Setenv("TFPROOF_ENVIRONMENT", "production")
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
	applyKey := ""
	for k := range s3.objects {
		if strings.HasPrefix(k, "tfproof/records/apply/") {
			v, _ := s3.current(k)
			r, ok, err := record.VerifyContent(v)
			if err != nil || !ok {
				t.Fatalf("apply record content check failed: ok=%v err=%v", ok, err)
			}
			applyRec, applyKey = r, k
		}
	}
	if applyRec == nil {
		t.Fatalf("no apply record; objects: %v", keys(s3.objects))
	}
	a := applyRec.Approval
	if a == nil || strings.Join(a.ApprovedBy, ",") != "bob" || strings.Join(a.EnvironmentApprovedBy, ",") != "dave" ||
		strings.Join(a.ChangeAuthors, ",") != "alice" || !a.IndependentApprover || !a.ApprovedHead || a.StaleApproval {
		b, _ := json.MarshalIndent(applyRec.Approval, "", " ")
		t.Fatalf("unexpected approval evidence: %s", b)
	}
	v := applyRec.Apply.Verification
	if v == nil || !v.Passed || v.SameRun == nil || !*v.SameRun || v.PullRequest == nil || !*v.PullRequest || !strings.HasPrefix(v.PullRequestRecord, "444-") {
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
	// Records are write-once: capturing the same apply again must not replace it.
	err = run([]string{"capture", "apply", "--workdir", wd, "--plan-json", "plan.json", "--exit-code", "1"})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second capture of the same apply should fail, got %v", err)
	}
	if n := len(s3.objects[applyKey]); n != 1 {
		t.Fatalf("apply record has %d versions, want 1", n)
	}

	// 3. A second apply with an unreviewed change set -> must show up as an exception.
	setRun(t, dir, "666", "workflow_dispatch", "othersha", `{}`)
	if err := run([]string{"capture", "apply", "--workdir", wd, "--plan-json", "evil.json", "--exit-code", "1", "--pr", "none"}); err != nil {
		t.Fatalf("capture apply (dispatch): %v", err)
	}

	// 4. Report.
	out := filepath.Join(dir, "evidence")
	report := func() string {
		t.Helper()
		if err := run([]string{"report", "--repo", "acme/infra", "--since", "2000-01-01", "--out-dir", out}); err != nil {
			t.Fatalf("report: %v", err)
		}
		md, _ := os.ReadFile(filepath.Join(out, "summary.md"))
		return string(md)
	}
	md := report()
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
	if !strings.Contains(md, "Applies with exceptions: **1**") || !strings.Contains(md, "Plans captured: **2**") {
		t.Fatalf("summary missing counts:\n%s", md)
	}

	// 5. A new version written over a record (bypassing tfproof) is flagged,
	// even though its content hash is self-consistent.
	orig, _ := s3.current(applyKey)
	forged, _, _ := record.VerifyContent(orig)
	forged.Apply.ExitCode = 0
	forged.Run.Actor = "mallory"
	fb, _ := record.Finalize(forged)
	s3.objects[applyKey] = append(s3.objects[applyKey], fb)
	if md := report(); !strings.Contains(md, "record overwritten (2 versions)") || !strings.Contains(md, "Applies with exceptions: **2**") {
		t.Fatalf("overwritten record not flagged:\n%s", md)
	}

	// 6. Altered bytes are detected by the content hash.
	s3.objects[applyKey] = [][]byte{[]byte(strings.Replace(string(orig), `"bob"`, `"mallory"`, 1))}
	if md := report(); !strings.Contains(md, "content hash mismatch") {
		t.Fatalf("tampered record not flagged:\n%s", md)
	}
}

// A plan on main must not replace the plan reviewed on the PR: otherwise the
// PR check compares main's plan with itself and always passes.
func TestPushPlanDoesNotReplaceReviewedPRPlan(t *testing.T) {
	dir, wd, _ := e2eEnv(t)
	setRun(t, dir, "444", "pull_request", "prmergeref", prEvent)
	if err := run([]string{"capture", "plan", "--workdir", wd, "--plan-json", "plan.json"}); err != nil {
		t.Fatal(err)
	}
	setRun(t, dir, "555", "push", "mergesha", `{"ref":"refs/heads/main"}`)
	if err := run([]string{"capture", "plan", "--workdir", wd, "--plan-json", "evil.json", "--plan-file", "tfplan"}); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"verify", "--workdir", wd, "--plan-json", "evil.json", "--plan-file", "tfplan", "--require-same-run", "--require-pr"})
	if ee, ok := err.(exitError); !ok || ee.code != 2 {
		t.Fatalf("main's plan differs from the one reviewed on PR #7; verify should exit 2, got %v", err)
	}
}

func keys(m map[string][][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
