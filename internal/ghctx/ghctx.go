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

	"github.com/hanging-rock-llc/soc2-tf/internal/httpretry"
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
	// PRHeadSHA is, for pull_request events, the head commit of the pull
	// request that was planned. Verification compares it with the head the
	// PR was merged at, so a plan of an earlier commit doesn't count.
	PRHeadSHA string `json:"pr_head_sha,omitempty"`
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
	if r.Event == "pull_request" {
		_, r.PRHeadSHA = PRFromEvent()
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

// PRFromEvent reads the pull request number and head commit from
// GITHUB_EVENT_PATH, if the triggering event carries them. issue_comment
// events on a pull request yield the number but no head commit.
func PRFromEvent() (number int, headSHA string) {
	p := os.Getenv("GITHUB_EVENT_PATH")
	if p == "" {
		return 0, ""
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return 0, ""
	}
	var ev struct {
		PullRequest struct {
			Number int `json:"number"`
			Head   struct {
				SHA string `json:"sha"`
			} `json:"head"`
		} `json:"pull_request"`
		Issue struct {
			Number      int             `json:"number"`
			PullRequest json.RawMessage `json:"pull_request"`
		} `json:"issue"`
	}
	if json.Unmarshal(b, &ev) != nil {
		return 0, ""
	}
	switch {
	case ev.PullRequest.Number != 0:
		return ev.PullRequest.Number, ev.PullRequest.Head.SHA
	case ev.Issue.Number != 0 && len(ev.Issue.PullRequest) > 0:
		return ev.Issue.Number, ""
	}
	return 0, ""
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
	resp, err := httpretry.Do(c.HTTP, func() (*http.Request, error) {
		req, err := http.NewRequest(http.MethodGet, c.BaseURL+path, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		if c.Token != "" {
			req.Header.Set("Authorization", "Bearer "+c.Token)
		}
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
// apply-on-merge workflows triggered by `push`). A PR whose merge commit is
// sha wins; otherwise the first merged PR containing sha. Open or closed
// unmerged PRs never count: their approvals don't cover what reached the
// branch. Returns 0 if none.
func (c *Client) PRForCommit(repo, sha string) (int, error) {
	var raw []struct {
		Number         int     `json:"number"`
		MergedAt       *string `json:"merged_at"`
		MergeCommitSHA string  `json:"merge_commit_sha"`
	}
	if err := c.get(fmt.Sprintf("/repos/%s/commits/%s/pulls", repo, sha), &raw); err != nil {
		return 0, err
	}
	first := 0
	for _, p := range raw {
		if p.MergedAt == nil {
			continue
		}
		if p.MergeCommitSHA == sha {
			return p.Number, nil
		}
		if first == 0 {
			first = p.Number
		}
	}
	return first, nil
}

// CommitAuthors returns the GitHub logins that authored or committed the
// pull request's commits. They are authors of the change too, so they can't
// be its independent approver. GitHub's own "web-flow" committer is skipped.
func (c *Client) CommitAuthors(repo string, n int) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	add := func(login string) {
		if login != "" && login != "web-flow" && !seen[login] {
			seen[login] = true
			out = append(out, login)
		}
	}
	for page := 1; page <= 3; page++ { // the API caps PR commits at 250
		var raw []struct {
			Author *struct {
				Login string `json:"login"`
			} `json:"author"`
			Committer *struct {
				Login string `json:"login"`
			} `json:"committer"`
		}
		if err := c.get(fmt.Sprintf("/repos/%s/pulls/%d/commits?per_page=100&page=%d", repo, n, page), &raw); err != nil {
			return nil, err
		}
		for _, cm := range raw {
			if cm.Author != nil {
				add(cm.Author.Login)
			}
			if cm.Committer != nil {
				add(cm.Committer.Login)
			}
		}
		if len(raw) < 100 {
			break
		}
	}
	sort.Strings(out)
	return out, nil
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
	// ChangeAuthors are everyone who authored the change: the PR author and
	// every author/committer of its commits (or, with no PR, the actor who
	// started the run). None of them counts as an independent approver.
	ChangeAuthors []string `json:"change_authors"`
	// ApprovedBy are reviewers whose most recent review is APPROVED.
	ApprovedBy []string `json:"approved_by"`
	// ApprovedHead is true if at least one approval was submitted against the
	// pull request's final head commit (i.e. not a stale approval).
	ApprovedHead bool `json:"approved_head"`
	// Environment is the deployment environment whose approvals count ("" =
	// any environment approved in the run).
	Environment string `json:"environment,omitempty"`
	// EnvironmentApprovedBy are users who approved the deployment environment
	// gate for this run.
	EnvironmentApprovedBy []string `json:"environment_approved_by"`
	// IndependentApprover is true when someone who didn't author the change
	// (and isn't a bot) approved either the PR's final commit or the
	// deployment: the separation-of-duties test auditors apply to CC8.1
	// samples. Approvals of earlier commits don't count.
	IndependentApprover bool `json:"independent_approver"`
	// StaleApproval is true when the PR was approved, but only on earlier
	// commits, and no independent environment approval covers the final one.
	StaleApproval      bool          `json:"stale_approval"`
	Reviews            []Review      `json:"reviews,omitempty"`
	EnvironmentReviews []EnvApproval `json:"environment_reviews,omitempty"`
}

// ApprovalInput is the raw approval evidence for one apply.
type ApprovalInput struct {
	PR            *PR
	Reviews       []Review
	EnvApprovals  []EnvApproval
	Environment   string   // only approvals of this environment count ("" = any)
	Actor         string   // author when there's no PR
	CommitAuthors []string // logins that authored or committed the PR's commits
}

// Evaluate computes approval evidence from raw reviews and env approvals.
func Evaluate(in ApprovalInput) Approval {
	a := Approval{
		ChangeAuthors: []string{}, ApprovedBy: []string{}, EnvironmentApprovedBy: []string{},
		Environment: in.Environment, Reviews: in.Reviews, EnvironmentReviews: in.EnvApprovals,
	}
	headSHA := ""
	if in.PR != nil {
		a.PRAuthor = in.PR.Author
		headSHA = in.PR.HeadSHA
	}
	authors := map[string]bool{}
	for _, u := range append([]string{a.PRAuthor}, in.CommitAuthors...) {
		if u != "" {
			authors[u] = true
		}
	}
	if len(authors) == 0 && in.Actor != "" {
		authors[in.Actor] = true
	}
	for u := range authors {
		a.ChangeAuthors = append(a.ChangeAuthors, u)
	}
	sort.Strings(a.ChangeAuthors)
	independent := func(u string) bool {
		return u != "" && !authors[u] && !strings.HasSuffix(u, "[bot]")
	}

	// Latest substantive review per user wins (COMMENTED doesn't override).
	latest := map[string]Review{}
	for _, r := range in.Reviews {
		if r.State == "COMMENTED" || r.State == "PENDING" {
			continue
		}
		if prev, ok := latest[r.User]; !ok || r.SubmittedAt.After(prev.SubmittedAt) {
			latest[r.User] = r
		}
	}
	independentHead := false
	for u, r := range latest {
		if r.State != "APPROVED" {
			continue
		}
		a.ApprovedBy = append(a.ApprovedBy, u)
		if headSHA != "" && r.CommitID == headSHA {
			a.ApprovedHead = true
			independentHead = independentHead || independent(u)
		}
	}
	sort.Strings(a.ApprovedBy)

	independentEnv := false
	seen := map[string]bool{}
	for _, e := range in.EnvApprovals {
		if e.State != "approved" || seen[e.User] || !coversEnvironment(e, in.Environment) {
			continue
		}
		seen[e.User] = true
		a.EnvironmentApprovedBy = append(a.EnvironmentApprovedBy, e.User)
		independentEnv = independentEnv || independent(e.User)
	}
	sort.Strings(a.EnvironmentApprovedBy)

	a.IndependentApprover = independentHead || independentEnv
	a.StaleApproval = len(a.ApprovedBy) > 0 && !a.ApprovedHead && !independentEnv
	return a
}

func coversEnvironment(e EnvApproval, env string) bool {
	if env == "" {
		return true
	}
	for _, name := range e.Environments {
		if name == env {
			return true
		}
	}
	return false
}
