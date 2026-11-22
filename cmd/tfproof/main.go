// Command tfproof captures tamper-evident evidence of Terraform/OpenTofu plans
// and applies run in CI, verifies that what gets applied is what was
// reviewed, and produces SOC 2 change-management evidence packs.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hanging-rock-llc/soc2-tf/internal/awsv4"
	"github.com/hanging-rock-llc/soc2-tf/internal/ghctx"
	"github.com/hanging-rock-llc/soc2-tf/internal/plan"
	"github.com/hanging-rock-llc/soc2-tf/internal/record"
	"github.com/hanging-rock-llc/soc2-tf/internal/report"
	"github.com/hanging-rock-llc/soc2-tf/internal/sink"
	"github.com/hanging-rock-llc/soc2-tf/internal/verify"
)

var version = "dev"

const usage = `tfproof - change-management evidence for Terraform and OpenTofu in CI

Usage:
  tfproof capture plan   [flags]   record a plan (run after terraform plan)
  tfproof verify         [flags]   gate: check the plan about to be applied is the reviewed plan
  tfproof capture apply  [flags]   record an apply (run after terraform apply, even on failure)
  tfproof report         [flags]   build an auditor evidence pack for a period
  tfproof version

Run "tfproof <command> -h" for flags. Every flag can also be set with an
environment variable: --sink -> TFPROOF_SINK, --workdir -> TFPROOF_WORKDIR, etc.
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		var ee exitError
		if errors.As(err, &ee) {
			fmt.Fprintln(os.Stderr, "tfproof:", ee.msg)
			os.Exit(ee.code)
		}
		fmt.Fprintln(os.Stderr, "tfproof:", err)
		os.Exit(1)
	}
}

type exitError struct {
	code int
	msg  string
}

func (e exitError) Error() string { return e.msg }

func run(args []string) error {
	if len(args) == 0 {
		fmt.Print(usage)
		return nil
	}
	switch args[0] {
	case "capture":
		if len(args) < 2 {
			return errors.New("capture needs a phase: plan or apply")
		}
		switch args[1] {
		case "plan":
			return cmdCapture(record.PhasePlan, args[2:])
		case "apply":
			return cmdCapture(record.PhaseApply, args[2:])
		}
		return fmt.Errorf("unknown capture phase %q (want plan or apply)", args[1])
	case "verify":
		return cmdVerify(args[1:])
	case "report":
		return cmdReport(args[1:])
	case "version", "--version", "-v":
		fmt.Println("tfproof", version)
		return nil
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	}
	return fmt.Errorf("unknown command %q\n\n%s", args[0], usage)
}

// envDefault returns $TFPROOF_<NAME> or def.
func envDefault(name, def string) string {
	if v := os.Getenv("TFPROOF_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))); v != "" {
		return v
	}
	return def
}

func envBool(name string) bool {
	b, _ := strconv.ParseBool(envDefault(name, "false"))
	return b
}

func envInt(name string, def int) int {
	if v, err := strconv.Atoi(envDefault(name, "")); err == nil {
		return v
	}
	return def
}

type common struct {
	sink, region, workdir, binary, planFile, planJSON, pr, token, lockMode string
	retainDays                                                             int
	noAWS, noGitHub                                                        bool
}

func (c *common) register(fs *flag.FlagSet) {
	fs.StringVar(&c.sink, "sink", envDefault("sink", ""), "evidence store: s3://bucket/prefix or a local directory")
	fs.StringVar(&c.region, "region", envDefault("region", ""), "AWS region for the evidence bucket (default $AWS_REGION)")
	fs.StringVar(&c.workdir, "workdir", envDefault("workdir", "."), "Terraform root module directory")
	fs.StringVar(&c.binary, "binary", envDefault("binary", "terraform"), "terraform or tofu")
	fs.StringVar(&c.planFile, "plan-file", envDefault("plan_file", ""), "binary plan file (relative to --workdir)")
	fs.StringVar(&c.planJSON, "plan-json", envDefault("plan_json", ""), "pre-rendered `show -json` output (skips running the binary)")
	fs.StringVar(&c.pr, "pr", envDefault("pr", "auto"), "pull request number, auto, or none")
	fs.StringVar(&c.token, "github-token", firstNonEmpty(os.Getenv("TFPROOF_GITHUB_TOKEN"), os.Getenv("GITHUB_TOKEN")), "token for reading PR reviews and environment approvals")
	fs.IntVar(&c.retainDays, "retain-days", envInt("retain_days", 0), "explicit per-object Object Lock retention (0 = bucket default)")
	fs.StringVar(&c.lockMode, "lock-mode", envDefault("lock_mode", "COMPLIANCE"), "Object Lock mode when --retain-days is set")
	fs.BoolVar(&c.noAWS, "no-aws-identity", envBool("no_aws_identity"), "don't call sts:GetCallerIdentity")
	fs.BoolVar(&c.noGitHub, "no-github-api", envBool("no_github_api"), "don't call the GitHub API")
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func (c *common) openSink() (sink.Sink, error) {
	return sink.Open(c.sink, sink.Options{Region: c.region, RetainDays: c.retainDays, LockMode: c.lockMode})
}

// loadPlan returns parsed facts and the plan file hash (if a file was given).
func (c *common) loadPlan() (*plan.Facts, string, error) {
	var data []byte
	var err error
	fileHash := ""
	if c.planFile != "" {
		p := c.planFile
		if !filepath.IsAbs(p) {
			p = filepath.Join(c.workdir, p)
		}
		if fileHash, err = plan.FileSHA256(p); err != nil {
			return nil, "", fmt.Errorf("hash plan file: %w", err)
		}
	}
	switch {
	case c.planJSON != "":
		p := c.planJSON
		if !filepath.IsAbs(p) {
			p = filepath.Join(c.workdir, p)
		}
		data, err = os.ReadFile(p)
	case c.planFile != "":
		data, err = plan.ShowJSON(c.binary, c.workdir, c.planFile)
	default:
		return nil, "", errors.New("need --plan-file or --plan-json")
	}
	if err != nil {
		return nil, "", err
	}
	f, err := plan.Parse(data)
	return f, fileHash, err
}

// resolvePR turns --pr into a number using the event payload or the API.
func (c *common) resolvePR(gh *ghctx.Client, run ghctx.Run) (int, string) {
	switch strings.ToLower(c.pr) {
	case "none", "0", "":
		return 0, ""
	case "auto":
		if n := ghctx.PRNumberFromEvent(); n > 0 {
			return n, ""
		}
		if gh != nil && run.SHA != "" && run.Provider == "github-actions" {
			n, err := gh.PRForCommit(run.Repository, run.SHA)
			if err != nil {
				return 0, "could not look up the pull request for " + run.SHA + ": " + err.Error()
			}
			return n, ""
		}
		return 0, ""
	default:
		n, err := strconv.Atoi(c.pr)
		if err != nil {
			return 0, "invalid --pr value " + strconv.Quote(c.pr)
		}
		return n, ""
	}
}

func (c *common) github() *ghctx.Client {
	// Only talk to the GitHub API from inside GitHub Actions, where the
	// GITHUB_* context identifies which repository and run to ask about.
	if c.noGitHub || c.token == "" || os.Getenv("GITHUB_ACTIONS") != "true" {
		return nil
	}
	return ghctx.NewClient(c.token)
}

func relWorkdir(w string) string {
	if ws := os.Getenv("GITHUB_WORKSPACE"); ws != "" {
		if abs, err := filepath.Abs(w); err == nil {
			if rel, err := filepath.Rel(ws, abs); err == nil && !strings.HasPrefix(rel, "..") {
				return filepath.ToSlash(rel)
			}
		}
	}
	return filepath.ToSlash(filepath.Clean(w))
}

func cmdCapture(phase record.Phase, args []string) error {
	fs := flag.NewFlagSet("capture "+string(phase), flag.ContinueOnError)
	var c common
	c.register(fs)
	exitCode := fs.Int("exit-code", envInt("exit_code", -1), "apply only: exit code of terraform apply (required)")
	logPath := fs.String("log", envDefault("log", ""), "apply only: path to captured apply output")
	uploadLog := fs.Bool("upload-log", envBool("upload_log"), "apply only: store the apply log next to the record (may contain sensitive output)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if phase == record.PhaseApply && *exitCode < 0 {
		return errors.New("capture apply needs --exit-code (pass the terraform apply exit status)")
	}
	s, err := c.openSink()
	if err != nil {
		return err
	}

	run := ghctx.FromEnv()
	workdir := relWorkdir(c.workdir)
	rec := &record.Record{
		Schema:     record.Schema,
		Phase:      phase,
		CapturedAt: time.Now().UTC(),
		Tool:       record.Tool{Name: "tfproof", Version: version},
		IaC:        record.IaC{Binary: c.binary, Workdir: workdir},
		Run:        run,
	}
	rec.ID = record.NewID(run, phase, workdir)

	// Plan facts. For apply, the plan is optional but strongly recommended:
	// it's what lets the record say *what* changed and verify it.
	facts, fileHash, perr := c.loadPlan()
	if perr != nil {
		if phase == record.PhasePlan {
			return perr
		}
		rec.Warnings = append(rec.Warnings, "plan not recorded: "+perr.Error())
	} else {
		rec.Plan = &record.PlanEvidence{FileSHA256: fileHash, Facts: *facts}
		rec.IaC.Version = facts.TerraformVersion
	}

	gh := c.github()
	if gh == nil && !c.noGitHub && run.Provider == "github-actions" {
		rec.Warnings = append(rec.Warnings, "no GitHub token: pull request and approval evidence not collected")
	}
	prNum, warn := c.resolvePR(gh, run)
	if warn != "" {
		rec.Warnings = append(rec.Warnings, warn)
	}
	if gh != nil && prNum > 0 {
		pr, err := gh.GetPR(run.Repository, prNum)
		if err != nil {
			rec.Warnings = append(rec.Warnings, "pull request lookup failed: "+err.Error())
		} else {
			rec.PullRequest = pr
		}
	} else if prNum > 0 {
		rec.PullRequest = &ghctx.PR{Number: prNum}
	}

	if phase == record.PhaseApply {
		// Approvals: PR reviews plus deployment environment approvals.
		if gh != nil {
			var reviews []ghctx.Review
			if rec.PullRequest != nil && rec.PullRequest.Number > 0 {
				if reviews, err = gh.Reviews(run.Repository, rec.PullRequest.Number); err != nil {
					rec.Warnings = append(rec.Warnings, "PR reviews lookup failed: "+err.Error())
				}
			}
			env, err := gh.EnvApprovals(run.Repository, run.RunID)
			if err != nil {
				rec.Warnings = append(rec.Warnings, "environment approvals lookup failed (needs actions: read): "+err.Error())
			}
			a := ghctx.Evaluate(rec.PullRequest, reviews, env, run.Actor)
			rec.Approval = &a
		}
		ae := &record.ApplyEvidence{ExitCode: *exitCode, Succeeded: *exitCode == 0}
		if *logPath != "" {
			b, err := os.ReadFile(*logPath)
			if err != nil {
				rec.Warnings = append(rec.Warnings, "apply log not read: "+err.Error())
			} else {
				ae.LogSHA256 = awsv4.HashHex(b)
				if *uploadLog {
					ae.LogKey = strings.TrimSuffix(record.Key(rec), ".json") + ".log"
					if err := s.Put(ae.LogKey, b, "text/plain; charset=utf-8"); err != nil {
						return fmt.Errorf("upload apply log: %w", err)
					}
				}
			}
		}
		if rec.Plan != nil {
			v, err := verify.Check(s, verify.Input{
				Repo: run.Repository, RunID: run.RunID, Workdir: workdir,
				FileHash: fileHash, Facts: facts, PR: prNumber(rec),
			})
			if err != nil {
				rec.Warnings = append(rec.Warnings, "verification could not run: "+err.Error())
			} else {
				ae.Verification = v
			}
		}
		rec.Apply = ae
	}

	if !c.noAWS {
		if creds, err := awsv4.FromEnv(); err == nil {
			id, err := awsv4.CallerIdentity(creds, firstNonEmpty(c.region, awsv4.Region()), nil)
			if err != nil {
				rec.Warnings = append(rec.Warnings, "caller identity lookup failed: "+err.Error())
			} else {
				rec.CloudIdentity = id
			}
		}
	}

	data, err := record.Finalize(rec)
	if err != nil {
		return err
	}
	key := record.Key(rec)
	if err := s.Put(key, data, "application/json"); err != nil {
		return fmt.Errorf("write record: %w", err)
	}
	if phase == record.PhasePlan {
		if err := s.Put(record.RunIndexKey(run.Repository, run.RunID, workdir), data, "application/json"); err != nil {
			return fmt.Errorf("write run index: %w", err)
		}
		if n := prNumber(rec); n > 0 {
			if err := s.Put(record.PRIndexKey(run.Repository, n, workdir), data, "application/json"); err != nil {
				return fmt.Errorf("write PR index: %w", err)
			}
		}
	}

	fmt.Printf("tfproof: recorded %s %s -> %s/%s\n", phase, rec.ID, s, key)
	for _, w := range rec.Warnings {
		fmt.Fprintln(os.Stderr, "tfproof: warning:", w)
		if run.Provider == "github-actions" {
			fmt.Printf("::warning title=tfproof::%s\n", w)
		}
	}
	writeOutputs(map[string]string{
		"record-id":        rec.ID,
		"record-key":       key,
		"content-sha256":   rec.ContentSHA256,
		"changeset-digest": digestOf(rec),
		"has-changes":      strconv.FormatBool(rec.Plan != nil && rec.Plan.HasChanges),
	})
	writeStepSummary(rec, s.String()+"/"+key)
	if phase == record.PhaseApply && rec.Apply.Verification != nil && !rec.Apply.Verification.Passed && run.Provider == "github-actions" {
		fmt.Println("::warning title=tfproof::applied plan was not verified against the reviewed plan; this apply will appear as an exception in the evidence report")
	}
	return nil
}

func prNumber(r *record.Record) int {
	if r.PullRequest != nil {
		return r.PullRequest.Number
	}
	return 0
}

func digestOf(r *record.Record) string {
	if r.Plan != nil {
		return r.Plan.ChangesetDigest
	}
	return ""
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	var c common
	c.register(fs)
	requireSameRun := fs.Bool("require-same-run", envBool("require_same_run"), "fail if no plan was captured earlier in this run")
	requirePR := fs.Bool("require-pr", envBool("require_pr"), "fail if no plan was captured on the pull request")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := c.openSink()
	if err != nil {
		return err
	}
	run := ghctx.FromEnv()
	facts, fileHash, err := c.loadPlan()
	if err != nil {
		return err
	}
	prNum, warn := c.resolvePR(c.github(), run)
	if warn != "" {
		fmt.Fprintln(os.Stderr, "tfproof: warning:", warn)
	}
	v, err := verify.Check(s, verify.Input{
		Repo: run.Repository, RunID: run.RunID, Workdir: relWorkdir(c.workdir),
		FileHash: fileHash, Facts: facts, PR: prNum,
		RequireSameRun: *requireSameRun, RequirePR: *requirePR,
	})
	if err != nil {
		return err
	}
	fmt.Println("tfproof:", verify.Summary(v))
	writeOutputs(map[string]string{"verified": strconv.FormatBool(v.Passed)})
	if !v.Passed {
		return exitError{code: 2, msg: "verification failed: " + strings.Join(v.Notes, "; ")}
	}
	return nil
}

func cmdReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	sinkURI := fs.String("sink", envDefault("sink", ""), "evidence store: s3://bucket/prefix or a local directory")
	region := fs.String("region", envDefault("region", ""), "AWS region for the evidence bucket")
	repo := fs.String("repo", envDefault("repo", ""), "owner/repo to report on (default: all)")
	since := fs.String("since", envDefault("since", ""), "start date YYYY-MM-DD (default: 1 year ago)")
	until := fs.String("until", envDefault("until", ""), "end date YYYY-MM-DD, exclusive (default: now)")
	out := fs.String("out-dir", envDefault("out_dir", "tfproof-evidence"), "directory for changes.csv and summary.md")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := sink.Open(*sinkURI, sink.Options{Region: *region})
	if err != nil {
		return err
	}
	opt := report.Options{Repo: *repo, Since: time.Now().UTC().AddDate(-1, 0, 0)}
	if *since != "" {
		if opt.Since, err = time.Parse("2006-01-02", *since); err != nil {
			return fmt.Errorf("--since: %w", err)
		}
	}
	if *until != "" {
		if opt.Until, err = time.Parse("2006-01-02", *until); err != nil {
			return fmt.Errorf("--until: %w", err)
		}
	}
	res, err := report.Build(s, opt)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	csvF, err := os.Create(filepath.Join(*out, "changes.csv"))
	if err != nil {
		return err
	}
	defer csvF.Close()
	if err := res.WriteCSV(csvF); err != nil {
		return err
	}
	mdF, err := os.Create(filepath.Join(*out, "summary.md"))
	if err != nil {
		return err
	}
	defer mdF.Close()
	if err := res.WriteMarkdown(mdF, s.String()); err != nil {
		return err
	}
	nex := 0
	for _, r := range res.Applies {
		if len(r.Exceptions) > 0 {
			nex++
		}
	}
	fmt.Printf("tfproof: %d applies, %d plans, %d exceptions -> %s/{changes.csv,summary.md}\n", len(res.Applies), res.PlanCount, nex, *out)
	return nil
}

func writeOutputs(kv map[string]string) {
	p := os.Getenv("GITHUB_OUTPUT")
	if p == "" {
		return
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	for k, v := range kv {
		fmt.Fprintf(f, "%s=%s\n", k, v)
	}
}

func writeStepSummary(r *record.Record, location string) {
	p := os.Getenv("GITHUB_STEP_SUMMARY")
	if p == "" {
		return
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	w := func(format string, a ...any) { fmt.Fprintf(f, format, a...) }
	w("### tfproof: %s recorded for `%s`\n\n", r.Phase, r.IaC.Workdir)
	if r.Plan != nil {
		s := r.Plan.Summary
		w("| create | update | replace | delete | import | forget |\n|---|---|---|---|---|---|\n")
		w("| %d | %d | %d | %d | %d | %d |\n\n", s.Create, s.Update, s.Replace, s.Delete, s.Import, s.Forget)
		if len(r.Plan.Changes) > 0 {
			w("<details><summary>%d changes</summary>\n\n", len(r.Plan.Changes))
			for i, c := range r.Plan.Changes {
				if i == 100 {
					w("- ... and %d more (see record)\n", len(r.Plan.Changes)-100)
					break
				}
				w("- `%s` %s\n", c.Action, c.Address)
			}
			w("\n</details>\n\n")
		}
	}
	if r.Apply != nil {
		status := "succeeded"
		if !r.Apply.Succeeded {
			status = fmt.Sprintf("failed (exit %d)", r.Apply.ExitCode)
		}
		w("- Apply: **%s**\n", status)
		if v := r.Apply.Verification; v != nil {
			mark := "✅ matches reviewed plan"
			if !v.Passed {
				mark = "⚠️ not verified: " + strings.Join(v.Notes, "; ")
			}
			w("- Plan verification: %s\n", mark)
		}
	}
	if a := r.Approval; a != nil {
		w("- Approved by: %s\n", orNone(append(append([]string{}, a.ApprovedBy...), a.EnvironmentApprovedBy...)))
		w("- Independent approver: %t\n", a.IndependentApprover)
	}
	if r.CloudIdentity != nil && r.CloudIdentity.RoleSessionName != "" {
		w("- AWS role session: `%s` (%s)\n", r.CloudIdentity.RoleSessionName, r.CloudIdentity.RoleName)
	}
	w("- Record: `%s`\n- content_sha256: `%s`\n\n", location, r.ContentSHA256)
}

func orNone(v []string) string {
	if len(v) == 0 {
		return "_none_"
	}
	return strings.Join(v, ", ")
}
