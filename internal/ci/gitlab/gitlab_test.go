package gitlab

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func client(t *testing.T, routes map[string]string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PRIVATE-TOKEN") != "glpat-test" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		body, ok := routes[r.URL.EscapedPath()]
		if !ok {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return &Client{BaseURL: srv.URL, Token: "glpat-test", Project: "acme/infra", JobID: "900", Environment: "production", HTTP: srv.Client()}
}

// An approval given before the last push covers the earlier head only.
func TestReviewsAttributeApprovalsToTheHeadAtApprovalTime(t *testing.T) {
	c := client(t, map[string]string{
		"/projects/acme%2Finfra/merge_requests/7/approvals": `{"approved_by":[
			{"user":{"username":"bob"},"approved_at":"2026-11-20T10:30:00Z"},
			{"user":{"username":"carol"},"approved_at":"2026-11-20T12:00:00Z"}]}`,
		"/projects/acme%2Finfra/merge_requests/7/versions": `[
			{"head_commit_sha":"h2","created_at":"2026-11-20T11:00:00Z"},
			{"head_commit_sha":"h1","created_at":"2026-11-20T10:00:00Z"}]`,
	})
	got, err := c.Reviews(7)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].User != "bob" || got[0].CommitID != "h1" || got[1].User != "carol" || got[1].CommitID != "h2" || got[0].State != "APPROVED" {
		t.Fatalf("Reviews = %+v", got)
	}
}

func TestPRForCommitOnlyMergedRequests(t *testing.T) {
	c := client(t, map[string]string{
		"/projects/acme%2Finfra/repository/commits/abc/merge_requests": `[
			{"iid":3,"state":"opened"},
			{"iid":5,"state":"merged","merge_commit_sha":"other"},
			{"iid":7,"state":"merged","squash_commit_sha":"abc"}]`,
	})
	n, err := c.PRForCommit("abc")
	if err != nil || n != 7 {
		t.Fatalf("PRForCommit = %d, %v; want 7 (squash commit match)", n, err)
	}
}

func TestCommitAuthorsArePushersToTheSourceBranch(t *testing.T) {
	c := client(t, map[string]string{
		"/projects/acme%2Finfra/merge_requests/7": `{"iid":7,"source_branch":"feature","created_at":"2026-11-20T09:00:00Z"}`,
		"/projects/acme%2Finfra/events": `[
			{"author":{"username":"alice"},"push_data":{"ref":"feature","ref_type":"branch"}},
			{"author":{"username":"bob"},"push_data":{"ref":"feature","ref_type":"branch"}},
			{"author":{"username":"mallory"},"push_data":{"ref":"main","ref_type":"branch"}},
			{"author":{"username":"alice"},"push_data":{"ref":"feature","ref_type":"branch"}}]`,
	})
	got, err := c.CommitAuthors(7)
	if err != nil || strings.Join(got, ",") != "alice,bob" {
		t.Fatalf("CommitAuthors = %v, %v", got, err)
	}
}

func TestEnvApprovalsOfThisJobsDeployment(t *testing.T) {
	c := client(t, map[string]string{
		"/projects/acme%2Finfra/deployments": `[{"id":41,"deployable":{"id":899}},{"id":42,"deployable":{"id":900}}]`,
		"/projects/acme%2Finfra/deployments/42": `{"id":42,"approvals":[
			{"user":{"username":"dave"},"status":"approved","comment":"ok"},
			{"user":{"username":"eve"},"status":"rejected"}]}`,
	})
	got, err := c.EnvApprovals()
	if err != nil || len(got) != 2 || got[0].User != "dave" || got[0].State != "approved" || got[0].Environments[0] != "production" {
		t.Fatalf("EnvApprovals = %+v, %v", got, err)
	}
}

func TestFromEnvMergeRequestPipeline(t *testing.T) {
	for k, v := range map[string]string{
		"CI_PROJECT_PATH": "acme/infra", "CI_PIPELINE_ID": "500", "CI_JOB_ID": "900", "CI_JOB_NAME": "plan",
		"CI_PIPELINE_SOURCE": "merge_request_event", "CI_MERGE_REQUEST_IID": "7", "CI_COMMIT_SHA": "headsha",
		"CI_MERGE_REQUEST_SOURCE_BRANCH_SHA": "", "GITLAB_USER_LOGIN": "alice", "TFPROOF_ENVIRONMENT": "", "CI_ENVIRONMENT_NAME": "",
	} {
		t.Setenv(k, v)
	}
	ctx := FromEnv()
	if !ctx.PlansPR || ctx.EventPR != 7 || ctx.Run.PRHeadSHA != "headsha" || ctx.Run.Provider != Provider || ctx.Run.RunAttempt != "900" {
		t.Fatalf("FromEnv = %+v", ctx)
	}
	t.Setenv("CI_PIPELINE_SOURCE", "push")
	if ctx := FromEnv(); ctx.PlansPR || ctx.Run.PRHeadSHA != "" {
		t.Fatalf("push pipeline must not count as planning the MR: %+v", ctx)
	}
}
