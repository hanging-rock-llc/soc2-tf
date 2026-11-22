// Package ci holds the CI-system-neutral evidence model: the run that
// produced a record, the pull/merge request it came from, and the evaluation
// of who approved it. Provider packages (ci/github, ci/gitlab) fill it in.
package ci

import (
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
	// PRHeadSHA is, for runs that plan a pull/merge request itself, the head
	// commit of the request that was planned. Verification compares it with
	// the head the request was merged at, so a plan of an earlier commit
	// doesn't count.
	PRHeadSHA string `json:"pr_head_sha,omitempty"`
}

// Context is what a provider knows about the current run.
type Context struct {
	Run Run
	// EventPR is the pull/merge request number the triggering event carries
	// (0 if none).
	EventPR int
	// PlansPR is true when this run plans the pull/merge request itself
	// (GitHub pull_request, GitLab merge_request_event), i.e. its plan is
	// what reviewers saw.
	PlansPR bool
	// Checkout is the directory the CI system checked the repository out
	// into (GITHUB_WORKSPACE, CI_PROJECT_DIR); workdirs are recorded
	// relative to it.
	Checkout string
}

// API reads change-approval evidence from the code host for one repository
// and run.
type API interface {
	GetPR(n int) (*PR, error)
	// PRForCommit finds the merged pull/merge request that produced sha.
	PRForCommit(sha string) (int, error)
	Reviews(n int) ([]Review, error)
	// CommitAuthors are the logins that authored or pushed the request's
	// commits.
	CommitAuthors(n int) ([]string, error)
	// EnvApprovals are approvals of deployments made by this run.
	EnvApprovals() ([]EnvApproval, error)
}

// PlansPREvent reports whether a recorded run planned a pull/merge request
// itself, so its plan is evidence of what was reviewed.
func PlansPREvent(provider, event string) bool {
	switch provider {
	case "gitlab-ci":
		return event == "merge_request_event"
	default:
		return event == "pull_request"
	}
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

// Review is one approval-relevant review of a pull/merge request.
type Review struct {
	User        string    `json:"user"`
	State       string    `json:"state"`
	CommitID    string    `json:"commit_id"`
	SubmittedAt time.Time `json:"submitted_at"`
}

// EnvApproval is one deployment-environment approval for a run.
type EnvApproval struct {
	User         string   `json:"user"`
	State        string   `json:"state"`
	Environments []string `json:"environments"`
	Comment      string   `json:"comment,omitempty"`
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
