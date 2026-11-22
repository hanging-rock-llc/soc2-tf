// Package report turns stored evidence records into an auditor-ready change
// population (CSV) and summary (Markdown) for a period.
package report

import (
	"encoding/csv"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hanging-rock-llc/soc2-tf/internal/record"
	"github.com/hanging-rock-llc/soc2-tf/internal/sink"
)

// Options select records.
type Options struct {
	Repo  string // owner/repo; empty = all
	Since time.Time
	Until time.Time // exclusive
}

// Row is one applied change (or a record that could not be read).
type Row struct {
	Rec        *record.Record
	Key        string
	ContentOK  bool
	Exceptions []string
}

// Result is the evaluated population.
type Result struct {
	Opt        Options
	Applies    []Row
	PlanCount  int
	Unreadable []string
}

func dayFromKey(key string) (time.Time, bool) {
	// records/<owner>/<repo>/<yyyy>/<mm>/<dd>/<id>.json
	p := strings.Split(key, "/")
	if len(p) < 7 || p[0] != "records" {
		return time.Time{}, false
	}
	n := len(p)
	t, err := time.Parse("2006/01/02", p[n-4]+"/"+p[n-3]+"/"+p[n-2])
	return t, err == nil
}

// Build loads and evaluates records.
func Build(s sink.Sink, opt Options) (*Result, error) {
	prefix := "records/"
	if opt.Repo != "" {
		prefix = "records/" + strings.Trim(opt.Repo, "/") + "/"
	}
	keys, err := s.List(prefix)
	if err != nil {
		return nil, err
	}
	res := &Result{Opt: opt}
	sinceDay := opt.Since.UTC().Truncate(24 * time.Hour)
	for _, k := range keys {
		if !strings.HasSuffix(k, ".json") {
			continue
		}
		day, ok := dayFromKey(k)
		if !ok || day.Before(sinceDay) || (!opt.Until.IsZero() && !day.Before(opt.Until)) {
			continue
		}
		b, err := s.Get(k)
		if err != nil {
			res.Unreadable = append(res.Unreadable, k+": "+err.Error())
			continue
		}
		r, contentOK, err := record.VerifyContent(b)
		if err != nil {
			res.Unreadable = append(res.Unreadable, k+": "+err.Error())
			continue
		}
		if r.CapturedAt.Before(opt.Since) || (!opt.Until.IsZero() && !r.CapturedAt.Before(opt.Until)) {
			continue
		}
		switch r.Phase {
		case record.PhasePlan:
			res.PlanCount++
		case record.PhaseApply:
			row := Row{Rec: r, Key: k, ContentOK: contentOK}
			row.Exceptions = exceptions(r, contentOK)
			res.Applies = append(res.Applies, row)
		}
	}
	sort.Slice(res.Applies, func(i, j int) bool {
		return res.Applies[i].Rec.CapturedAt.Before(res.Applies[j].Rec.CapturedAt)
	})
	return res, nil
}

func exceptions(r *record.Record, contentOK bool) []string {
	var ex []string
	if !contentOK {
		ex = append(ex, "record content hash mismatch")
	}
	a := r.Approval
	if a == nil || (len(a.ApprovedBy) == 0 && len(a.EnvironmentApprovedBy) == 0) {
		ex = append(ex, "no approval recorded")
	} else if !a.IndependentApprover {
		ex = append(ex, "no approver independent of the author")
	}
	if a != nil && len(a.ApprovedBy) > 0 && !a.ApprovedHead && len(a.EnvironmentApprovedBy) == 0 {
		ex = append(ex, "PR approval predates the final commit")
	}
	if r.Apply == nil || r.Apply.Verification == nil || !r.Apply.Verification.Checked {
		ex = append(ex, "applied plan not verified against reviewed plan")
	} else if !r.Apply.Verification.Passed {
		ex = append(ex, "applied plan did not match reviewed plan")
	}
	return ex
}

var csvHeader = []string{
	"captured_at", "repository", "workdir", "record_id", "run_url", "actor",
	"pr_number", "pr_url", "pr_author", "approved_by", "environment_approved_by",
	"independent_approver", "approved_final_commit", "plan_verified",
	"exit_code", "succeeded", "create", "update", "replace", "delete",
	"changeset_digest", "role_session_name", "record_key", "content_hash_ok", "exceptions",
}

// WriteCSV writes the change population, one row per apply.
func (res *Result) WriteCSV(w io.Writer) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(csvHeader); err != nil {
		return err
	}
	for _, row := range res.Applies {
		r := row.Rec
		var prNum, prURL, prAuthor string
		if r.PullRequest != nil {
			prNum, prURL, prAuthor = strconv.Itoa(r.PullRequest.Number), r.PullRequest.URL, r.PullRequest.Author
		}
		var approved, envApproved, indep, head string
		if r.Approval != nil {
			approved = strings.Join(r.Approval.ApprovedBy, " ")
			envApproved = strings.Join(r.Approval.EnvironmentApprovedBy, " ")
			indep = strconv.FormatBool(r.Approval.IndependentApprover)
			head = strconv.FormatBool(r.Approval.ApprovedHead)
		}
		verified, exit, ok := "", "", ""
		if r.Apply != nil {
			exit, ok = strconv.Itoa(r.Apply.ExitCode), strconv.FormatBool(r.Apply.Succeeded)
			if r.Apply.Verification != nil {
				verified = strconv.FormatBool(r.Apply.Verification.Passed)
			}
		}
		var c, u, rp, d, digest string
		if r.Plan != nil {
			c, u, rp, d = strconv.Itoa(r.Plan.Summary.Create), strconv.Itoa(r.Plan.Summary.Update),
				strconv.Itoa(r.Plan.Summary.Replace), strconv.Itoa(r.Plan.Summary.Delete)
			digest = r.Plan.ChangesetDigest
		}
		session := ""
		if r.CloudIdentity != nil {
			session = r.CloudIdentity.RoleSessionName
		}
		if err := cw.Write([]string{
			r.CapturedAt.UTC().Format(time.RFC3339), r.Run.Repository, r.IaC.Workdir, r.ID, r.Run.RunURL, r.Run.Actor,
			prNum, prURL, prAuthor, approved, envApproved, indep, head, verified,
			exit, ok, c, u, rp, d, digest, session, row.Key, strconv.FormatBool(row.ContentOK),
			strings.Join(row.Exceptions, "; "),
		}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// WriteMarkdown writes the summary an auditor reads first.
func (res *Result) WriteMarkdown(w io.Writer, source string) error {
	var ex []Row
	failed := 0
	for _, row := range res.Applies {
		if len(row.Exceptions) > 0 {
			ex = append(ex, row)
		}
		if row.Rec.Apply != nil && !row.Rec.Apply.Succeeded {
			failed++
		}
	}
	scope := res.Opt.Repo
	if scope == "" {
		scope = "all repositories"
	}
	until := "now"
	if !res.Opt.Until.IsZero() {
		until = res.Opt.Until.UTC().Format("2006-01-02")
	}
	p := func(format string, a ...any) { fmt.Fprintf(w, format, a...) }
	p("# Infrastructure change evidence\n\n")
	p("| | |\n|---|---|\n")
	p("| Scope | %s |\n", scope)
	p("| Period | %s to %s (UTC) |\n", res.Opt.Since.UTC().Format("2006-01-02"), until)
	p("| Evidence store | `%s` |\n", source)
	p("| Generated | %s |\n\n", time.Now().UTC().Format(time.RFC3339))
	p("## Population\n\n")
	p("- Infrastructure applies (changes to production): **%d**\n", len(res.Applies))
	p("- Plans captured: **%d**\n", res.PlanCount)
	p("- Applies that failed (non-zero exit): **%d**\n", failed)
	p("- Applies with exceptions: **%d**\n", len(ex))
	if len(res.Unreadable) > 0 {
		p("- Records that could not be read: **%d**\n", len(res.Unreadable))
	}
	p("\nEvery apply is listed in `changes.csv` with its pull request, approvers, the identity that ran it, and whether the applied plan matched the reviewed plan. Each row links to an immutable JSON record whose `content_sha256` can be recomputed independently.\n\n")
	p("## Exceptions\n\n")
	if len(ex) == 0 {
		p("None. Every apply in the period had an independent approval and a verified plan.\n\n")
	} else {
		p("| When (UTC) | Repository | Workdir | Run | Exceptions |\n|---|---|---|---|---|\n")
		for _, row := range ex {
			r := row.Rec
			run := r.ID
			if r.Run.RunURL != "" {
				run = fmt.Sprintf("[%s](%s)", r.Run.RunID, r.Run.RunURL)
			}
			p("| %s | %s | %s | %s | %s |\n", r.CapturedAt.UTC().Format("2006-01-02 15:04"), r.Run.Repository, r.IaC.Workdir, run, strings.Join(row.Exceptions, "; "))
		}
		p("\n")
	}
	if len(res.Unreadable) > 0 {
		p("## Unreadable records\n\n")
		for _, u := range res.Unreadable {
			p("- `%s`\n", u)
		}
		p("\n")
	}
	p("## Control mapping (SOC 2)\n\n")
	p("- **CC8.1 Change management**: each change has a pull request, a recorded approval by someone other than the author, and proof the applied plan matched the approved plan.\n")
	p("- **CC6.1 / CC6.3 Logical access**: changes run under short-lived, CI-scoped role sessions (`role_session_name`), not personal credentials.\n")
	p("- **CC7.2 Monitoring**: records are written to an Object Lock bucket and can be correlated with CloudTrail by role session name.\n")
	return nil
}
