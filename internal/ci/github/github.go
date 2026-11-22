// Package github reads GitHub Actions run context and change-approval
// evidence (pull request reviews and deployment environment approvals).
package github

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/hanging-rock-llc/soc2-tf/internal/ci"
	"github.com/hanging-rock-llc/soc2-tf/internal/httpretry"
)

// FromEnv reads the standard GITHUB_* variables. Outside GitHub Actions it
// returns a "local" run so the tool is still usable for testing.
func FromEnv() ci.Context {
	r := ci.Run{
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
	ctx := ci.Context{PlansPR: r.Event == "pull_request"}
	ctx.EventPR, r.PRHeadSHA = prFromEvent()
	if !ctx.PlansPR {
		r.PRHeadSHA = ""
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
	ctx.Run = r
	return ctx
}

// prFromEvent reads the pull request number and head commit from
// GITHUB_EVENT_PATH, if the triggering event carries them. issue_comment
// events on a pull request yield the number but no head commit.
func prFromEvent() (number int, headSHA string) {
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

// Client is a tiny GitHub REST client for one repository and run.
type Client struct {
	BaseURL string
	Token   string
	Repo    string // owner/repo
	RunID   string
	HTTP    *http.Client
}

var _ ci.API = (*Client)(nil)

// NewClient uses GITHUB_API_URL and the given token (usually GITHUB_TOKEN).
func NewClient(token, repo, runID string) *Client {
	base := os.Getenv("GITHUB_API_URL")
	if base == "" {
		base = "https://api.github.com"
	}
	return &Client{BaseURL: strings.TrimRight(base, "/"), Token: token, Repo: repo, RunID: runID, HTTP: &http.Client{Timeout: 30 * time.Second}}
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

// GetPR fetches pull request metadata.
func (c *Client) GetPR(n int) (*ci.PR, error) {
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
	if err := c.get(fmt.Sprintf("/repos/%s/pulls/%d", c.Repo, n), &raw); err != nil {
		return nil, err
	}
	pr := &ci.PR{
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
func (c *Client) PRForCommit(sha string) (int, error) {
	var raw []struct {
		Number         int     `json:"number"`
		MergedAt       *string `json:"merged_at"`
		MergeCommitSHA string  `json:"merge_commit_sha"`
	}
	if err := c.get(fmt.Sprintf("/repos/%s/commits/%s/pulls", c.Repo, sha), &raw); err != nil {
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
func (c *Client) CommitAuthors(n int) ([]string, error) {
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
		if err := c.get(fmt.Sprintf("/repos/%s/pulls/%d/commits?per_page=100&page=%d", c.Repo, n, page), &raw); err != nil {
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
func (c *Client) Reviews(n int) ([]ci.Review, error) {
	var out []ci.Review
	for page := 1; page <= 10; page++ {
		var raw []struct {
			User struct {
				Login string `json:"login"`
			} `json:"user"`
			State       string    `json:"state"`
			CommitID    string    `json:"commit_id"`
			SubmittedAt time.Time `json:"submitted_at"`
		}
		if err := c.get(fmt.Sprintf("/repos/%s/pulls/%d/reviews?per_page=100&page=%d", c.Repo, n, page), &raw); err != nil {
			return nil, err
		}
		for _, r := range raw {
			out = append(out, ci.Review{User: r.User.Login, State: r.State, CommitID: r.CommitID, SubmittedAt: r.SubmittedAt})
		}
		if len(raw) < 100 {
			break
		}
	}
	return out, nil
}

// EnvApprovals fetches deployment environment approvals for this workflow run.
// Requires `actions: read`.
func (c *Client) EnvApprovals() ([]ci.EnvApproval, error) {
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
	if err := c.get(fmt.Sprintf("/repos/%s/actions/runs/%s/approvals", c.Repo, c.RunID), &raw); err != nil {
		return nil, err
	}
	out := make([]ci.EnvApproval, 0, len(raw))
	for _, r := range raw {
		envs := make([]string, 0, len(r.Environments))
		for _, e := range r.Environments {
			envs = append(envs, e.Name)
		}
		out = append(out, ci.EnvApproval{User: r.User.Login, State: r.State, Environments: envs, Comment: r.Comment})
	}
	return out, nil
}
