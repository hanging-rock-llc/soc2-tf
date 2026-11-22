// Package ghctx gathers GitHub Actions run context and change-approval
// evidence (pull request reviews and deployment environment approvals).
package ghctx

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// Run describes the CI run that produced a record.
type Run struct {
	Provider        string `json:"provider"`
	Repository      string `json:"repository"`
	Workflow        string `json:"workflow,omitempty"`
	WorkflowRef     string `json:"workflow_ref,omitempty"`
	Job             string `json:"job,omitempty"`
	RunID           string `json:"run_id"`
	RunAttempt      string `json:"run_attempt"`
	RunURL          string `json:"run_url,omitempty"`
	Event           string `json:"event,omitempty"`
	Ref             string `json:"ref,omitempty"`
	SHA             string `json:"sha"`
	Actor           string `json:"actor,omitempty"`
	TriggeringActor string `json:"triggering_actor,omitempty"`
	Environment     string `json:"environment,omitempty"`
}

// FromEnv reads the standard GITHUB_* variables. Outside GitHub Actions it
// returns a "local" run so the tool is still usable for testing.
func FromEnv() Run {
	r := Run{
		Provider:        "github-actions",
		Repository:      os.Getenv("GITHUB_REPOSITORY"),
		Workflow:        os.Getenv("GITHUB_WORKFLOW"),
		WorkflowRef:     os.Getenv("GITHUB_WORKFLOW_REF"),
		Job:             os.Getenv("GITHUB_JOB"),
		RunID:           os.Getenv("GITHUB_RUN_ID"),
		RunAttempt:      os.Getenv("GITHUB_RUN_ATTEMPT"),
		Event:           os.Getenv("GITHUB_EVENT_NAME"),
		Ref:             os.Getenv("GITHUB_REF"),
		SHA:             os.Getenv("GITHUB_SHA"),
		Actor:           os.Getenv("GITHUB_ACTOR"),
		TriggeringActor: os.Getenv("GITHUB_TRIGGERING_ACTOR"),
		Environment:     os.Getenv("TFPROOF_ENVIRONMENT"),
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		r.Provider = "local"
	}
	if r.RunID == "" {
		// Outside CI, all invocations share one logical run so a local
		// plan -> verify -> apply sequence links up. Override with
		// TFPROOF_RUN_ID to separate local runs.
		r.RunID = os.Getenv("TFPROOF_RUN_ID")
		if r.RunID == "" {
			r.RunID = "local"
		}
	}
	if r.RunAttempt == "" {
		r.RunAttempt = "1"
	}
	if r.Repository == "" {
		r.Repository = "local/local"
	}
	server := os.Getenv("GITHUB_SERVER_URL")
	if server == "" {
		server = "https://github.com"
	}
	if os.Getenv("GITHUB_RUN_ID") != "" {
		r.RunURL = fmt.Sprintf("%s/%s/actions/runs/%s/attempts/%s", server, r.Repository, r.RunID, r.RunAttempt)
	}
	return r
}

// PRNumberFromEvent reads the pull request number from GITHUB_EVENT_PATH,
// if the triggering event carries one.
func PRNumberFromEvent() int {
	p := os.Getenv("GITHUB_EVENT_PATH")
	if p == "" {
		return 0
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return 0
	}
	var ev struct {
		Number      int `json:"number"`
		PullRequest struct {
			Number int `json:"number"`
		} `json:"pull_request"`
		Issue struct {
			Number      int             `json:"number"`
			PullRequest json.RawMessage `json:"pull_request"`
		} `json:"issue"`
	}
	if json.Unmarshal(b, &ev) != nil {
		return 0
	}
	switch {
	case ev.PullRequest.Number != 0:
		return ev.PullRequest.Number
	case ev.Issue.Number != 0 && len(ev.Issue.PullRequest) > 0:
		return ev.Issue.Number
	}
	return 0
}

// Client is a tiny GitHub REST client.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// NewClient uses GITHUB_API_URL and the given token (usually GITHUB_TOKEN).
func NewClient(token string) *Client {
	base := os.Getenv("GITHUB_API_URL")
	if base == "" {
		base = "https://api.github.com"
	}
	return &Client{BaseURL: strings.TrimRight(base, "/"), Token: token, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

func (c *Client) get(path string, out any) error {
	req, err := http.NewRequest(http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("github GET %s: %s: %s", path, resp.Status, strings.TrimSpace(string(b)))
	}
	return json.Unmarshal(b, out)
}

// PR is the subset of pull request data recorded as evidence.
type PR struct {
	Number   int    `json:"number"`
	URL      string `json:"url"`
	Title    string `json:"title"`
	Author   string `json:"author"`
	HeadSHA  string `json:"head_sha"`
	BaseRef  string `json:"base_ref"`
	Merged   bool   `json:"merged"`
	MergedBy string `json:"merged_by,omitempty"`
	MergeSHA string `json:"merge_commit_sha,omitempty"`
}

// Review is one pull request review.
type Review struct {
	User        string    `json:"user"`
	State       string    `json:"state"`
	CommitID    string    `json:"commit_id"`
	SubmittedAt time.Time `json:"submitted_at"`
}

// EnvApproval is one deployment-environment approval on a workflow run.
type EnvApproval struct {
	User         string   `json:"user"`
	State        string   `json:"state"`
	Environments []string `json:"environments"`
	Comment      string   `json:"comment,omitempty"`
}

// GetPR fetches pull request metadata.
func (c *Client) GetPR(repo string, n int) (*PR, error) {
	var raw struct {
		Number  int    `json:"number"`
		HTMLURL string `json:"html_url"`
		Title   string `json:"title"`
		User    struct {
			Login string `json:"login"`
		} `json:"user"`
		Head struct {
			SHA string `json:"sha"`
		} `json:"head"`
		Base struct {
			Ref string `json:"ref"`
		} `json:"base"`
		Merged         bool   `json:"merged"`
		MergeCommitSHA string `json:"merge_commit_sha"`
		MergedBy       *struct {
			Login string `json:"login"`
		} `json:"merged_by"`
	}
	if err := c.get(fmt.Sprintf("/repos/%s/pulls/%d", repo, n), &raw); err != nil {
		return nil, err
	}
	pr := &PR{
		Number: raw.Number, URL: raw.HTMLURL, Title: raw.Title, Author: raw.User.Login,
		HeadSHA: raw.Head.SHA, BaseRef: raw.Base.Ref, Merged: raw.Merged, MergeSHA: raw.MergeCommitSHA,
	}
	if raw.MergedBy != nil {
		pr.MergedBy = raw.MergedBy.Login
	}
	return pr, nil
}

// PRForCommit finds the merged pull request that produced sha (for
// apply-on-merge workflows triggered by `push`). Returns 0 if none.
func (c *Client) PRForCommit(repo, sha string) (int, error) {
	var raw []struct {
		Number   int     `json:"number"`
		MergedAt *string `json:"merged_at"`
	}
	if err := c.get(fmt.Sprintf("/repos/%s/commits/%s/pulls", repo, sha), &raw); err != nil {
		return 0, err
	}
	for _, p := range raw {
		if p.MergedAt != nil {
			return p.Number, nil
		}
	}
	if len(raw) > 0 {
		return raw[0].Number, nil
	}
	return 0, nil
}

// Reviews fetches all reviews on a pull request.
func (c *Client) Reviews(repo string, n int) ([]Review, error) {
	var out []Review
	for page := 1; page <= 10; page++ {
		var raw []struct {
			User struct {
				Login string `json:"login"`
			} `json:"user"`
			State       string    `json:"state"`
			CommitID    string    `json:"commit_id"`
			SubmittedAt time.Time `json:"submitted_at"`
		}
		if err := c.get(fmt.Sprintf("/repos/%s/pulls/%d/reviews?per_page=100&page=%d", repo, n, page), &raw); err != nil {
			return nil, err
		}
		for _, r := range raw {
			out = append(out, Review{User: r.User.Login, State: r.State, CommitID: r.CommitID, SubmittedAt: r.SubmittedAt})
		}
		if len(raw) < 100 {
			break
		}
	}
	return out, nil
}

// EnvApprovals fetches deployment environment approvals for a workflow run.
// Requires `actions: read`.
func (c *Client) EnvApprovals(repo, runID string) ([]EnvApproval, error) {
	var raw []struct {
		State        string `json:"state"`
		Comment      string `json:"comment"`
		Environments []struct {
			Name string `json:"name"`
		} `json:"environments"`
		User struct {
			Login string `json:"login"`
		} `json:"user"`
	}
	if err := c.get(fmt.Sprintf("/repos/%s/actions/runs/%s/approvals", repo, runID), &raw); err != nil {
		return nil, err
	}
	out := make([]EnvApproval, 0, len(raw))
	for _, r := range raw {
		envs := make([]string, 0, len(r.Environments))
		for _, e := range r.Environments {
			envs = append(envs, e.Name)
		}
		out = append(out, EnvApproval{User: r.User.Login, State: r.State, Environments: envs, Comment: r.Comment})
	}
	return out, nil
}

// Approval is the evaluated approval evidence for a change.
type Approval struct {
	PRAuthor string `json:"pr_author,omitempty"`
	// ApprovedBy are reviewers whose most recent review is APPROVED.
	ApprovedBy []string `json:"approved_by"`
	// ApprovedHead is true if at least one approval was submitted against the
	// pull request's final head commit (i.e. not a stale approval).
	ApprovedHead bool `json:"approved_head"`
	// EnvironmentApprovedBy are users who approved the deployment environment
	// gate for this run.
	EnvironmentApprovedBy []string `json:"environment_approved_by"`
	// IndependentApprover is true when someone other than the change author
	// approved it: the separation-of-duties test auditors apply to CC8.1
	// samples.
	IndependentApprover bool          `json:"independent_approver"`
	Reviews             []Review      `json:"reviews,omitempty"`
	EnvironmentReviews  []EnvApproval `json:"environment_reviews,omitempty"`
}

// Evaluate computes approval evidence from raw reviews and env approvals.
func Evaluate(pr *PR, reviews []Review, env []EnvApproval, actor string) Approval {
	a := Approval{ApprovedBy: []string{}, EnvironmentApprovedBy: []string{}, Reviews: reviews, EnvironmentReviews: env}
	headSHA := ""
	if pr != nil {
		a.PRAuthor = pr.Author
		headSHA = pr.HeadSHA
	}
	// Latest substantive review per user wins (COMMENTED doesn't override).
	latest := map[string]Review{}
	for _, r := range reviews {
		if r.State == "COMMENTED" || r.State == "PENDING" {
			continue
		}
		if prev, ok := latest[r.User]; !ok || r.SubmittedAt.After(prev.SubmittedAt) {
			latest[r.User] = r
		}
	}
	for u, r := range latest {
		if r.State == "APPROVED" {
			a.ApprovedBy = append(a.ApprovedBy, u)
			if headSHA != "" && r.CommitID == headSHA {
				a.ApprovedHead = true
			}
		}
	}
	sort.Strings(a.ApprovedBy)
	seen := map[string]bool{}
	for _, e := range env {
		if e.State == "approved" && !seen[e.User] {
			seen[e.User] = true
			a.EnvironmentApprovedBy = append(a.EnvironmentApprovedBy, e.User)
		}
	}
	sort.Strings(a.EnvironmentApprovedBy)
	// The person who authored the change must not be its only approver. With
	// no pull request (e.g. workflow_dispatch), the author is the actor who
	// started the run.
	author := a.PRAuthor
	if author == "" {
		author = actor
	}
	for _, u := range append(append([]string{}, a.ApprovedBy...), a.EnvironmentApprovedBy...) {
		if u != "" && u != author {
			a.IndependentApprover = true
			break
		}
	}
	return a
}
