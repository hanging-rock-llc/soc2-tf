// Package gitlab reads GitLab CI run context and change-approval evidence
// (merge request approvals and protected-environment deployment approvals).
//
// The API calls need a token with read_api (a project access token with the
// Reporter role); CI_JOB_TOKEN can't read approvals or merge request
// versions.
package gitlab

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/hanging-rock-llc/soc2-tf/internal/ci"
	"github.com/hanging-rock-llc/soc2-tf/internal/httpretry"
)

// Provider is the value recorded in run.provider.
const Provider = "gitlab-ci"

// FromEnv reads GitLab's predefined CI/CD variables.
//
// GitLab has no run attempt; run_attempt holds the job ID, which changes
// when a job is retried, so a retried capture gets a new record.
func FromEnv() ci.Context {
	r := ci.Run{
		Provider:    Provider,
		Repository:  os.Getenv("CI_PROJECT_PATH"),
		Job:         os.Getenv("CI_JOB_NAME"),
		RunID:       os.Getenv("CI_PIPELINE_ID"),
		RunAttempt:  os.Getenv("CI_JOB_ID"),
		RunURL:      os.Getenv("CI_PIPELINE_URL"),
		Event:       os.Getenv("CI_PIPELINE_SOURCE"),
		Ref:         os.Getenv("CI_COMMIT_REF_NAME"),
		SHA:         os.Getenv("CI_COMMIT_SHA"),
		Actor:       os.Getenv("GITLAB_USER_LOGIN"),
		Environment: firstNonEmpty(os.Getenv("TFPROOF_ENVIRONMENT"), os.Getenv("CI_ENVIRONMENT_NAME")),
	}
	ctx := ci.Context{PlansPR: r.Event == "merge_request_event"}
	if iid := os.Getenv("CI_MERGE_REQUEST_IID"); iid != "" {
		fmt.Sscanf(iid, "%d", &ctx.EventPR)
	}
	if ctx.PlansPR {
		// Merged-results pipelines set the source branch head explicitly;
		// detached merge request pipelines run on it, so it's CI_COMMIT_SHA.
		r.PRHeadSHA = firstNonEmpty(os.Getenv("CI_MERGE_REQUEST_SOURCE_BRANCH_SHA"), r.SHA)
	}
	ctx.Run = r
	return ctx
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// Client is a tiny GitLab REST client for one project and job.
type Client struct {
	BaseURL     string // API v4 root, e.g. https://gitlab.com/api/v4
	Token       string
	Project     string // ID or full path
	JobID       string
	Environment string // deployment environment of this job ("" = none)
	HTTP        *http.Client
}

var _ ci.API = (*Client)(nil)

// NewClient uses CI_API_V4_URL, CI_PROJECT_ID and CI_JOB_ID.
func NewClient(token, environment string) *Client {
	base := firstNonEmpty(os.Getenv("CI_API_V4_URL"), "https://gitlab.com/api/v4")
	return &Client{
		BaseURL: strings.TrimRight(base, "/"), Token: token,
		Project: firstNonEmpty(os.Getenv("CI_PROJECT_ID"), os.Getenv("CI_PROJECT_PATH")),
		JobID:   os.Getenv("CI_JOB_ID"), Environment: environment,
		HTTP: &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) get(path string, out any) error {
	resp, err := httpretry.Do(c.HTTP, func() (*http.Request, error) {
		req, err := http.NewRequest(http.MethodGet, c.BaseURL+path, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("PRIVATE-TOKEN", c.Token)
		return req, nil
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("gitlab GET %s: %s: %s", path, resp.Status, strings.TrimSpace(string(b)))
	}
	return json.Unmarshal(b, out)
}

func (c *Client) project() string { return "/projects/" + url.PathEscape(c.Project) }

type user struct {
	Username string `json:"username"`
}

type mergeRequest struct {
	IID             int       `json:"iid"`
	WebURL          string    `json:"web_url"`
	Title           string    `json:"title"`
	Author          user      `json:"author"`
	SHA             string    `json:"sha"`
	SourceBranch    string    `json:"source_branch"`
	TargetBranch    string    `json:"target_branch"`
	State           string    `json:"state"`
	MergeUser       *user     `json:"merge_user"`
	MergedBy        *user     `json:"merged_by"` // deprecated in favor of merge_user
	MergeCommitSHA  string    `json:"merge_commit_sha"`
	SquashCommitSHA string    `json:"squash_commit_sha"`
	CreatedAt       time.Time `json:"created_at"`
}

func (c *Client) mergeRequest(iid int) (*mergeRequest, error) {
	var mr mergeRequest
	if err := c.get(fmt.Sprintf("%s/merge_requests/%d", c.project(), iid), &mr); err != nil {
		return nil, err
	}
	return &mr, nil
}

// GetPR fetches merge request metadata.
func (c *Client) GetPR(iid int) (*ci.PR, error) {
	mr, err := c.mergeRequest(iid)
	if err != nil {
		return nil, err
	}
	pr := &ci.PR{
		Number: mr.IID, URL: mr.WebURL, Title: mr.Title, Author: mr.Author.Username,
		HeadSHA: mr.SHA, BaseRef: mr.TargetBranch, Merged: mr.State == "merged",
		MergeSHA: firstNonEmpty(mr.MergeCommitSHA, mr.SquashCommitSHA),
	}
	switch {
	case mr.MergeUser != nil:
		pr.MergedBy = mr.MergeUser.Username
	case mr.MergedBy != nil:
		pr.MergedBy = mr.MergedBy.Username
	}
	return pr, nil
}

// PRForCommit finds the merged merge request that produced sha. One whose
// merge or squash commit is sha wins; otherwise the first merged one.
func (c *Client) PRForCommit(sha string) (int, error) {
	var mrs []mergeRequest
	if err := c.get(fmt.Sprintf("%s/repository/commits/%s/merge_requests", c.project(), url.PathEscape(sha)), &mrs); err != nil {
		return 0, err
	}
	first := 0
	for _, mr := range mrs {
		if mr.State != "merged" {
			continue
		}
		if mr.MergeCommitSHA == sha || mr.SquashCommitSHA == sha {
			return mr.IID, nil
		}
		if first == 0 {
			first = mr.IID
		}
	}
	return first, nil
}

// Reviews returns the merge request's current approvals. GitLab doesn't
// record which commit an approval was for, so each is attributed to the
// head of the latest diff version pushed before it was given: an approval
// followed by a push is stale, like a GitHub review on an older commit.
func (c *Client) Reviews(iid int) ([]ci.Review, error) {
	var approvals struct {
		ApprovedBy []struct {
			User       user       `json:"user"`
			ApprovedAt *time.Time `json:"approved_at"`
		} `json:"approved_by"`
	}
	if err := c.get(fmt.Sprintf("%s/merge_requests/%d/approvals", c.project(), iid), &approvals); err != nil {
		return nil, err
	}
	var versions []struct {
		HeadCommitSHA string    `json:"head_commit_sha"`
		CreatedAt     time.Time `json:"created_at"`
	}
	if err := c.get(fmt.Sprintf("%s/merge_requests/%d/versions", c.project(), iid), &versions); err != nil {
		return nil, err
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i].CreatedAt.Before(versions[j].CreatedAt) })
	out := make([]ci.Review, 0, len(approvals.ApprovedBy))
	for _, a := range approvals.ApprovedBy {
		r := ci.Review{User: a.User.Username, State: "APPROVED"}
		if a.ApprovedAt != nil {
			r.SubmittedAt = *a.ApprovedAt
			for _, v := range versions {
				if v.CreatedAt.After(r.SubmittedAt) {
					break
				}
				r.CommitID = v.HeadCommitSHA
			}
		}
		out = append(out, r)
	}
	return out, nil
}

// CommitAuthors returns the usernames that pushed to the merge request's
// source branch since it was opened. GitLab's commit API only has author
// names and emails, so pushes (from the project's events) are what links
// commits to accounts. Pushes to a fork's branch aren't visible here.
func (c *Client) CommitAuthors(iid int) ([]string, error) {
	mr, err := c.mergeRequest(iid)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	after := mr.CreatedAt.AddDate(0, 0, -1).Format("2006-01-02") // `after` is exclusive and day-granular
	for page := 1; page <= 20; page++ {
		var events []struct {
			Author   user `json:"author"`
			PushData struct {
				Ref     string `json:"ref"`
				RefType string `json:"ref_type"`
			} `json:"push_data"`
		}
		if err := c.get(fmt.Sprintf("%s/events?action=pushed&after=%s&per_page=100&page=%d", c.project(), after, page), &events); err != nil {
			return nil, err
		}
		for _, e := range events {
			if e.PushData.RefType == "branch" && e.PushData.Ref == mr.SourceBranch && e.Author.Username != "" && !seen[e.Author.Username] {
				seen[e.Author.Username] = true
				out = append(out, e.Author.Username)
			}
		}
		if len(events) < 100 {
			break
		}
	}
	sort.Strings(out)
	return out, nil
}

// EnvApprovals returns the approvals of the deployment this job created
// (protected environments with approval rules, GitLab Premium/Ultimate).
func (c *Client) EnvApprovals() ([]ci.EnvApproval, error) {
	if c.Environment == "" || c.JobID == "" {
		return nil, nil
	}
	var deployments []struct {
		ID         int `json:"id"`
		Deployable *struct {
			ID int `json:"id"`
		} `json:"deployable"`
	}
	q := url.Values{"environment": {c.Environment}, "order_by": {"id"}, "sort": {"desc"}, "per_page": {"100"}}
	if err := c.get(c.project()+"/deployments?"+q.Encode(), &deployments); err != nil {
		return nil, err
	}
	for _, d := range deployments {
		if d.Deployable == nil || fmt.Sprint(d.Deployable.ID) != c.JobID {
			continue
		}
		var dep struct {
			Approvals []struct {
				User    user   `json:"user"`
				Status  string `json:"status"`
				Comment string `json:"comment"`
			} `json:"approvals"`
		}
		if err := c.get(fmt.Sprintf("%s/deployments/%d", c.project(), d.ID), &dep); err != nil {
			return nil, err
		}
		out := make([]ci.EnvApproval, 0, len(dep.Approvals))
		for _, a := range dep.Approvals {
			out = append(out, ci.EnvApproval{User: a.User.Username, State: a.Status, Environments: []string{c.Environment}, Comment: a.Comment})
		}
		return out, nil
	}
	return nil, nil
}
