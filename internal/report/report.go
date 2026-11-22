// Package report turns stored evidence records into an auditor-ready change
// population (CSV) and summary (Markdown) for a period.
package report

import (
	"encoding/csv"
	"fmt"
	"io"
	"path"
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

// Row is one applied change.
type Row struct {
	Rec        *record.Record
	Key        string
	ContentOK  bool
	Exceptions []string
}

// Result is the evaluated population.
type Result struct {
	Opt     Options
	Applies []Row
	// NoOpApplies counts applies whose recorded plan changed nothing; they
	// are left out of the population.
	NoOpApplies int
	PlanCount   int
	// Integrity lists stored objects that were overwritten, deleted, could
	// not be read, or whose key doesn't match their content.
	Integrity []string
}

// parseKey splits records/<phase>/<owner>/<repo>/<yyyy>/<mm>/<dd>/<id>.json.
func parseKey(key string) (phase, repo, id string, day time.Time, ok bool) {
	p := strings.Split(key, "/")
	if len(p) != 8 || p[0] != "records" || !strings.HasSuffix(p[7], ".json") {
		return "", "", "", time.Time{}, false
	}
	t, err := time.Parse("2006/01/02", p[4]+"/"+p[5]+"/"+p[6])
	if err != nil {
		return "", "", "", time.Time{}, false
	}
	return p[1], p[2] + "/" + p[3], strings.TrimSuffix(p[7], ".json"), t, true
}

// Build loads and evaluates records.
func Build(s sink.Sink, opt Options) (*Result, error) {
	repo := strings.Trim(opt.Repo, "/")
	var objs []sink.Object
	for _, phase := range []record.Phase{record.PhasePlan, record.PhaseApply} {
		prefix := path.Join("records", string(phase)) + "/"
		if repo != "" {
			prefix += repo + "/"
		}
		o, err := s.List(prefix)
		if err != nil {
			return nil, err
		}
		objs = append(objs, o...)
	}
	res := &Result{Opt: opt}
	sinceDay := opt.Since.UTC().Truncate(24 * time.Hour)
	for _, o := range objs {
		k := o.Key
		phase, keyRepo, id, day, ok := parseKey(k)
		if !ok {
			if strings.HasSuffix(k, ".json") {
				res.Integrity = append(res.Integrity, k+": unexpected object in the records area")
			}
			continue
		}
		if day.Before(sinceDay) || (!opt.Until.IsZero() && !day.Before(opt.Until)) {
			continue
		}
		if o.Deleted {
			res.Integrity = append(res.Integrity, k+": record deleted (current version is a delete marker)")
			continue
		}
		b, err := s.Get(k)
		if err != nil {
			res.Integrity = append(res.Integrity, k+": "+err.Error())
			continue
		}
		r, contentOK, err := record.VerifyContent(b)
		if err != nil {
			res.Integrity = append(res.Integrity, k+": "+err.Error())
			continue
		}
		if r.CapturedAt.Before(opt.Since) || (!opt.Until.IsZero() && !r.CapturedAt.Before(opt.Until)) {
			continue
		}
		var integrity []string
		if o.Versions > 1 {
			integrity = append(integrity, fmt.Sprintf("record overwritten (%d versions)", o.Versions))
		}
		if string(r.Phase) != phase || r.Run.Repository != keyRepo || r.ID != id || r.CapturedAt.UTC().Format("2006-01-02") != day.Format("2006-01-02") {
			integrity = append(integrity, "record key does not match its content")
		}
		for _, f := range integrity {
			res.Integrity = append(res.Integrity, k+": "+f)
		}
		switch r.Phase {
		case record.PhasePlan:
			res.PlanCount++
		case record.PhaseApply:
			if r.Plan != nil && !r.Plan.HasChanges && contentOK && len(integrity) == 0 {
				res.NoOpApplies++
				continue
			}
			row := Row{Rec: r, Key: k, ContentOK: contentOK}
			row.Exceptions = append(exceptions(r, contentOK), integrity...)
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
	if a != nil && a.StaleApproval {
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
	"captured_at", "repository", "workdir", "unit", "record_id", "run_url", "actor",
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
			r.CapturedAt.UTC().Format(time.RFC3339), r.Run.Repository, r.IaC.Workdir, record.UnitKey(r.IaC), r.ID, r.Run.RunURL, r.Run.Actor,
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

// cell makes a value safe inside a Markdown table cell.
func cell(s string) string {
	return strings.NewReplacer("|", `\|`, "\r", " ", "\n", " ").Replace(s)
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
	p("| Scope | %s |\n", cell(scope))
	p("| Period | %s to %s (UTC) |\n", res.Opt.Since.UTC().Format("2006-01-02"), until)
	p("| Evidence store | `%s` |\n", cell(source))
	p("| Generated | %s |\n\n", time.Now().UTC().Format(time.RFC3339))
	p("## Population\n\n")
	p("- Infrastructure applies that changed something: **%d**\n", len(res.Applies))
	p("- Applies whose plan had no changes (not listed): **%d**\n", res.NoOpApplies)
	p("- Plans captured: **%d**\n", res.PlanCount)
	p("- Applies that failed (non-zero exit): **%d**\n", failed)
	p("- Applies with exceptions: **%d**\n", len(ex))
	if len(res.Integrity) > 0 {
		p("- Evidence integrity findings: **%d**\n", len(res.Integrity))
	}
	p("\nEvery apply recorded by `tfproof capture apply` is listed in `changes.csv` with its pull request, approvers, the identity that ran it, and whether the applied plan matched the reviewed plan. Each row points to a JSON record in a write-once Object Lock bucket whose `content_sha256` can be recomputed independently. Applies made without tfproof (outside CI, or from a workflow that skips it) are not in this population; reconcile against CloudTrail.\n\n")
	p("## Exceptions\n\n")
	if len(ex) == 0 {
		p("None. Every apply in the period had an independent approval and a verified plan.\n\n")
	} else {
		p("| When (UTC) | Repository | Unit | Run | Exceptions |\n|---|---|---|---|---|\n")
		for _, row := range ex {
			r := row.Rec
			run := cell(r.ID)
			if r.Run.RunURL != "" {
				run = fmt.Sprintf("[%s](%s)", cell(r.Run.RunID), cell(r.Run.RunURL))
			}
			p("| %s | %s | %s | %s | %s |\n", r.CapturedAt.UTC().Format("2006-01-02 15:04"), cell(r.Run.Repository), cell(record.UnitKey(r.IaC)), run, cell(strings.Join(row.Exceptions, "; ")))
		}
		p("\n")
	}
	if len(res.Integrity) > 0 {
		p("## Evidence integrity findings\n\n")
		p("Records are written once. Each finding below means a record was rewritten, removed, unreadable, or stored under a key that doesn't match it; compare against the object's version history.\n\n")
		for _, u := range res.Integrity {
			p("- `%s`\n", strings.ReplaceAll(u, "`", "'"))
		}
		p("\n")
	}
	p("## Control mapping (SOC 2)\n\n")
	p("- **CC8.1 Change management**: each change has a pull request, a recorded approval by someone other than its authors, and proof the applied plan matched the approved plan.\n")
	p("- **CC6.1 / CC6.3 Logical access**: changes run under short-lived, CI-scoped role sessions (`role_session_name`), not personal credentials.\n")
	p("- **CC7.2 Monitoring**: records are written once to an Object Lock bucket and can be correlated with CloudTrail by role session name.\n")
	return nil
}
