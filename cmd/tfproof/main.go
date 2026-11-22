// Command tfproof captures tamper-evident evidence of Terraform/OpenTofu plans
// and applies run in CI, verifies that what gets applied is what was
// reviewed, and produces SOC 2 change-management evidence packs.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/hanging-rock-llc/soc2-tf/internal/awsv4"
	"github.com/hanging-rock-llc/soc2-tf/internal/ci"
	"github.com/hanging-rock-llc/soc2-tf/internal/ci/github"
	"github.com/hanging-rock-llc/soc2-tf/internal/ci/gitlab"
	"github.com/hanging-rock-llc/soc2-tf/internal/cloudtrail"
	"github.com/hanging-rock-llc/soc2-tf/internal/grc"
	"github.com/hanging-rock-llc/soc2-tf/internal/kms"
	"github.com/hanging-rock-llc/soc2-tf/internal/plan"
	"github.com/hanging-rock-llc/soc2-tf/internal/record"
	"github.com/hanging-rock-llc/soc2-tf/internal/report"
	"github.com/hanging-rock-llc/soc2-tf/internal/s3"
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
  tfproof publish vanta  [flags]   upload the evidence pack to a Vanta document
  tfproof publish drata  [flags]   attach the evidence pack to a Drata evidence item
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
	case "publish":
		if len(args) < 2 {
			return errors.New("publish needs a target: vanta or drata")
		}
		return cmdPublish(args[1], args[2:])
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

func envDuration(name string, def time.Duration) time.Duration {
	if v, err := time.ParseDuration(envDefault(name, "")); err == nil {
		return v
	}
	return def
}

type common struct {
	sink, region, workdir, binary, planFile, planJSON, pr, githubToken, gitlabToken, lockMode, stack, kmsKey string
	retainDays                                                                                               int
	noAWS, noCIAPI                                                                                           bool
}

func (c *common) register(fs *flag.FlagSet) {
	fs.StringVar(&c.sink, "sink", envDefault("sink", ""), "evidence store: s3://bucket/prefix or a local directory")
	fs.StringVar(&c.region, "region", envDefault("region", ""), "AWS region for the evidence bucket (default $AWS_REGION)")
	fs.StringVar(&c.workdir, "workdir", envDefault("workdir", "."), "Terraform root module directory")
	fs.StringVar(&c.binary, "binary", envDefault("binary", "terraform"), "terraform or tofu")
	fs.StringVar(&c.planFile, "plan-file", envDefault("plan_file", ""), "binary plan file (relative to --workdir)")
	fs.StringVar(&c.planJSON, "plan-json", envDefault("plan_json", ""), "pre-rendered `show -json` output (skips running the binary)")
	fs.StringVar(&c.stack, "stack", envDefault("stack", ""), "name for this root module instance when one workdir is planned several ways (e.g. per var file); default: workdir + workspace")
	fs.StringVar(&c.pr, "pr", envDefault("pr", "auto"), "pull/merge request number, auto, or none")
	fs.StringVar(&c.githubToken, "github-token", firstNonEmpty(os.Getenv("TFPROOF_GITHUB_TOKEN"), os.Getenv("GITHUB_TOKEN")), "GitHub token for reading PR reviews and environment approvals")
	fs.StringVar(&c.gitlabToken, "gitlab-token", envDefault("gitlab_token", ""), "GitLab token with read_api (project access token, Reporter) for reading merge request approvals")
	fs.StringVar(&c.kmsKey, "kms-key-id", envDefault("kms_key_id", ""), "capture: KMS key (ID, ARN or alias) used to sign each record")
	fs.IntVar(&c.retainDays, "retain-days", envInt("retain_days", 0), "explicit per-object Object Lock retention (0 = bucket default)")
	fs.StringVar(&c.lockMode, "lock-mode", envDefault("lock_mode", "COMPLIANCE"), "Object Lock mode when --retain-days is set")
	fs.BoolVar(&c.noAWS, "no-aws-identity", envBool("no_aws_identity"), "don't call sts:GetCallerIdentity")
	fs.BoolVar(&c.noCIAPI, "no-ci-api", envBool("no_ci_api"), "don't call the GitHub/GitLab API")
}

// ciContext detects the CI system: GitLab CI, else GitHub Actions (which
// also covers local runs outside CI).
func ciContext() ci.Context {
	if os.Getenv("GITLAB_CI") == "true" {
		return gitlab.FromEnv()
	}
	return github.FromEnv()
}

// api returns a client for approval evidence, or nil (with the reason) when
// it can't or shouldn't be used. It only talks to the API from inside CI,
// where the environment identifies the repository and run to ask about.
func (c *common) api(run ci.Run) (ci.API, string) {
	if c.noCIAPI {
		return nil, ""
	}
	switch run.Provider {
	case "github-actions":
		if c.githubToken == "" {
			return nil, "no GitHub token: pull request and approval evidence not collected"
		}
		return github.NewClient(c.githubToken, run.Repository, run.RunID), ""
	case gitlab.Provider:
		if c.gitlabToken == "" {
			return nil, "no GitLab token (TFPROOF_GITLAB_TOKEN, read_api): merge request and approval evidence not collected"
		}
		return gitlab.NewClient(c.gitlabToken, run.Environment), ""
	}
	return nil, ""
}

// iac describes the root module instance being planned or applied.
func (c *common) iac() record.IaC {
	return record.IaC{Binary: c.binary, Workdir: relWorkdir(c.workdir), Workspace: workspace(c.workdir), Stack: c.stack}
}

// workspace returns the selected Terraform/OpenTofu workspace, or "" for
// default: $TF_WORKSPACE, else the name `workspace select` stored in the
// data directory.
func workspace(workdir string) string {
	ws := os.Getenv("TF_WORKSPACE")
	if ws == "" {
		dataDir := firstNonEmpty(os.Getenv("TF_DATA_DIR"), ".terraform")
		if !filepath.IsAbs(dataDir) {
			dataDir = filepath.Join(workdir, dataDir)
		}
		if b, err := os.ReadFile(filepath.Join(dataDir, "environment")); err == nil {
			ws = strings.TrimSpace(string(b))
		}
	}
	if ws == "default" {
		return ""
	}
	return ws
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

// resolvePR turns --pr into a number using the event or the API.
func (c *common) resolvePR(api ci.API, ctx ci.Context) (int, string) {
	switch strings.ToLower(c.pr) {
	case "none", "0", "":
		return 0, ""
	case "auto":
		if ctx.EventPR > 0 {
			return ctx.EventPR, ""
		}
		if api != nil && ctx.Run.SHA != "" {
			n, err := api.PRForCommit(ctx.Run.SHA)
			if err != nil {
				return 0, "could not look up the pull request for " + ctx.Run.SHA + ": " + err.Error()
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

// relWorkdir makes w relative to the CI checkout so records name the same
// workdir wherever the runner put the repository.
func relWorkdir(w string) string {
	if ws := firstNonEmpty(os.Getenv("GITHUB_WORKSPACE"), os.Getenv("CI_PROJECT_DIR")); ws != "" {
		if abs, err := filepath.Abs(w); err == nil {
			if rel, err := filepath.Rel(ws, abs); err == nil {
				if rel = filepath.ToSlash(rel); rel != ".." && !strings.HasPrefix(rel, "../") {
					return rel
				}
			}
		}
	}
	return filepath.ToSlash(filepath.Clean(w))
}

// sign writes a detached KMS signature for a stored record.
func (c *common) sign(s sink.Sink, key string, data []byte) error {
	k, err := kms.New(c.region)
	if err != nil {
		return err
	}
	sig, keyARN, err := k.SignDigest(c.kmsKey, sha256.Sum256(data))
	if err != nil {
		return err
	}
	b, err := json.Marshal(record.NewSignature(data, kms.Algorithm, keyARN, sig))
	if err != nil {
		return err
	}
	return s.Create(record.SignatureKey(key), b, "application/json")
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

	ctx := ciContext()
	run := ctx.Run
	rec := &record.Record{
		Schema:     record.Schema,
		Phase:      phase,
		CapturedAt: time.Now().UTC(),
		Tool:       record.Tool{Name: "tfproof", Version: version},
		IaC:        c.iac(),
		Run:        run,
	}
	unit := record.UnitKey(rec.IaC)
	rec.ID = record.NewID(run, phase, unit)

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

	api, why := c.api(run)
	if why != "" {
		rec.Warnings = append(rec.Warnings, why)
	}
	prNum, warn := c.resolvePR(api, ctx)
	if warn != "" {
		rec.Warnings = append(rec.Warnings, warn)
	}
	if api != nil && prNum > 0 {
		pr, err := api.GetPR(prNum)
		if err != nil {
			rec.Warnings = append(rec.Warnings, "pull request lookup failed: "+err.Error())
			rec.PullRequest = &ci.PR{Number: prNum}
		} else {
			rec.PullRequest = pr
		}
	} else if prNum > 0 {
		rec.PullRequest = &ci.PR{Number: prNum}
	}

	if phase == record.PhaseApply {
		// Approvals: PR reviews, plus deployment-environment approvals where
		// the plan offers them (GitHub: public repos or Enterprise; GitLab:
		// Premium/Ultimate protected environments).
		if api != nil {
			in := ci.ApprovalInput{PR: rec.PullRequest, Environment: run.Environment, Actor: run.Actor}
			if n := prNumber(rec); n > 0 {
				if in.Reviews, err = api.Reviews(n); err != nil {
					rec.Warnings = append(rec.Warnings, "PR reviews lookup failed: "+err.Error())
				}
				if in.CommitAuthors, err = api.CommitAuthors(n); err != nil {
					rec.Warnings = append(rec.Warnings, "PR commit authors lookup failed (only the PR author is treated as an author): "+err.Error())
				}
			}
			if in.EnvApprovals, err = api.EnvApprovals(); err != nil {
				rec.Warnings = append(rec.Warnings, "environment approvals lookup failed: "+err.Error())
			}
			if run.Environment == "" && len(in.EnvApprovals) > 0 {
				rec.Warnings = append(rec.Warnings, "environment not set: approvals of any deployment environment in this run were counted (set the environment input)")
			}
			a := ci.Evaluate(in)
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
					if err := s.Create(ae.LogKey, b, "text/plain; charset=utf-8"); err != nil {
						return fmt.Errorf("upload apply log: %w", err)
					}
				}
			}
		}
		if rec.Plan != nil {
			in := verify.Input{
				Repo: run.Repository, RunID: run.RunID, Unit: unit,
				FileHash: fileHash, Facts: facts, PR: prNumber(rec),
			}
			if rec.PullRequest != nil {
				in.PRHeadSHA = rec.PullRequest.HeadSHA
			}
			v, err := verify.Check(s, in)
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
	if err := s.Create(key, data, "application/json"); err != nil {
		if errors.Is(err, sink.ErrExists) {
			return fmt.Errorf("write record: %w (one capture per job, phase and unit; use --stack to tell units apart)", err)
		}
		return fmt.Errorf("write record: %w", err)
	}
	if c.kmsKey != "" {
		// The record is already stored; a signing failure fails the step and
		// the report lists the record as unsigned.
		if err := c.sign(s, key, data); err != nil {
			return fmt.Errorf("sign record %s: %w", key, err)
		}
	}
	if phase == record.PhasePlan {
		if err := s.Put(record.RunIndexKey(run.Repository, run.RunID, unit), data, "application/json"); err != nil {
			return fmt.Errorf("write run index: %w", err)
		}
		// Only a plan of the pull request itself is evidence of what was
		// reviewed. A push-to-main plan that merely resolves to a merged PR
		// must not replace it, or the PR check would compare main's plan
		// with itself.
		if ctx.PlansPR && run.PRHeadSHA != "" && ctx.EventPR > 0 && ctx.EventPR == prNumber(rec) {
			if err := s.Put(record.PRIndexKey(run.Repository, ctx.EventPR, unit), data, "application/json"); err != nil {
				return fmt.Errorf("write PR index: %w", err)
			}
		}
	}

	fmt.Printf("tfproof: recorded %s %s -> %s/%s\n", phase, rec.ID, s, key)
	for _, w := range rec.Warnings {
		warning(run, w)
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

// warning prints w to stderr and, in GitHub Actions, as an annotation. The
// message is escaped so text from API errors or terraform output can't
// smuggle in further workflow commands.
func warning(run ci.Run, w string) {
	fmt.Fprintln(os.Stderr, "tfproof: warning:", w)
	if run.Provider == "github-actions" {
		fmt.Printf("::warning title=tfproof::%s\n", escapeData(w))
	}
}

// escapeData escapes a workflow command message the way @actions/core does.
func escapeData(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(s)
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
	ctx := ciContext()
	run := ctx.Run
	facts, fileHash, err := c.loadPlan()
	if err != nil {
		return err
	}
	api, why := c.api(run)
	if why != "" {
		warning(run, why)
	}
	prNum, warn := c.resolvePR(api, ctx)
	if warn != "" {
		warning(run, warn)
	}
	in := verify.Input{
		Repo: run.Repository, RunID: run.RunID, Unit: record.UnitKey(c.iac()),
		FileHash: fileHash, Facts: facts, PR: prNum,
		RequireSameRun: *requireSameRun, RequirePR: *requirePR,
	}
	if api != nil && prNum > 0 {
		if pr, err := api.GetPR(prNum); err != nil {
			warning(run, "pull request lookup failed: "+err.Error())
		} else {
			in.PRHeadSHA = pr.HeadSHA
		}
	}
	v, err := verify.Check(s, in)
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
	planKey := fs.String("plan-signing-key", envDefault("plan_signing_key", ""), "KMS key that must have signed every plan record")
	applyKey := fs.String("apply-signing-key", envDefault("apply_signing_key", ""), "KMS key that must have signed every apply record")
	trail := fs.String("cloudtrail", envDefault("cloudtrail", ""), "S3 location of CloudTrail logs up to the account directory, e.g. s3://trail-bucket/AWSLogs/{account}; lists each apply's AWS API calls")
	trailRegions := fs.String("cloudtrail-regions", envDefault("cloudtrail_regions", ""), "comma-separated regions whose CloudTrail logs to read (default: $AWS_REGION and us-east-1)")
	trailBucketRegion := fs.String("cloudtrail-bucket-region", envDefault("cloudtrail_bucket_region", ""), "region of the CloudTrail bucket (default: --region)")
	lookback := fs.Duration("cloudtrail-lookback", envDuration("cloudtrail_lookback", time.Hour), "how far before each apply record to look for its session's API calls (at least the apply role's session duration)")
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
	if *planKey != "" || *applyKey != "" {
		k, err := kms.New(*region)
		if err != nil {
			return err
		}
		opt.Keys = k
		opt.SigningKeys = map[record.Phase]string{record.PhasePlan: *planKey, record.PhaseApply: *applyKey}
	}
	res, err := report.Build(s, opt)
	if err != nil {
		return err
	}
	if *trail != "" {
		src, err := trailSource(*trail, firstNonEmpty(*trailBucketRegion, *region), *trailRegions)
		if err != nil {
			return err
		}
		if err := res.JoinCloudTrail(src, *lookback); err != nil {
			return err
		}
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
	files := "changes.csv,summary.md"
	if res.CloudTrail {
		callsF, err := os.Create(filepath.Join(*out, "api-calls.csv"))
		if err != nil {
			return err
		}
		defer callsF.Close()
		if err := res.WriteAPICalls(callsF); err != nil {
			return err
		}
		files += ",api-calls.csv"
	}
	nex := 0
	for _, r := range res.Applies {
		if len(r.Exceptions) > 0 {
			nex++
		}
	}
	fmt.Printf("tfproof: %d applies, %d plans, %d exceptions -> %s/{%s}\n", len(res.Applies), res.PlanCount, nex, *out, files)
	return nil
}

// trailSource parses s3://bucket/prefix into a CloudTrail log reader.
func trailSource(uri, bucketRegion, regions string) (*cloudtrail.Source, error) {
	rest, ok := strings.CutPrefix(uri, "s3://")
	bucket, prefix, _ := strings.Cut(rest, "/")
	if !ok || bucket == "" || prefix == "" {
		return nil, fmt.Errorf("--cloudtrail must be s3://bucket/path/to/AWSLogs/{account}, got %q", uri)
	}
	c, err := s3.New(bucket, bucketRegion)
	if err != nil {
		return nil, err
	}
	var rs []string
	for _, r := range strings.Split(firstNonEmpty(regions, strings.Trim(awsv4.Region()+",us-east-1", ",")), ",") {
		if r = strings.TrimSpace(r); r != "" && !slices.Contains(rs, r) {
			rs = append(rs, r)
		}
	}
	return &cloudtrail.Source{Client: c, Prefix: strings.Trim(prefix, "/"), Regions: rs}, nil
}

// evidenceFiles reads what `tfproof report` wrote to dir.
func evidenceFiles(dir string) ([]grc.File, error) {
	var files []grc.File
	for _, f := range []struct{ name, contentType string }{
		{"summary.md", "text/markdown"},
		{"changes.csv", "text/csv"},
		{"api-calls.csv", "text/csv"},
	} {
		b, err := os.ReadFile(filepath.Join(dir, f.name))
		if errors.Is(err, os.ErrNotExist) && f.name == "api-calls.csv" {
			continue // only written when the report joined CloudTrail
		}
		if err != nil {
			return nil, fmt.Errorf("read evidence pack (run tfproof report first): %w", err)
		}
		files = append(files, grc.File{Name: f.name, ContentType: f.contentType, Data: b})
	}
	return files, nil
}

func cmdPublish(target string, args []string) error {
	fs := flag.NewFlagSet("publish "+target, flag.ContinueOnError)
	dir := fs.String("dir", envDefault("dir", "tfproof-evidence"), "directory containing changes.csv and summary.md from tfproof report")
	var publish func(files []grc.File) error
	switch target {
	case "vanta":
		doc := fs.String("document-id", envDefault("vanta_document_id", ""), "Vanta document to upload to (credentials: VANTA_CLIENT_ID, VANTA_CLIENT_SECRET)")
		publish = func(files []grc.File) error {
			id, secret := os.Getenv("VANTA_CLIENT_ID"), os.Getenv("VANTA_CLIENT_SECRET")
			if *doc == "" || id == "" || secret == "" {
				return errors.New("publish vanta needs --document-id, VANTA_CLIENT_ID and VANTA_CLIENT_SECRET")
			}
			desc := "tfproof infrastructure change evidence, generated " + time.Now().UTC().Format("2006-01-02")
			return grc.NewVanta(id, secret).Publish(*doc, desc, files)
		}
	case "drata":
		ws := fs.Int("workspace-id", envInt("drata_workspace_id", 0), "Drata workspace ID")
		ev := fs.Int("evidence-id", envInt("drata_evidence_id", 0), "Drata evidence item to attach to (credentials: DRATA_API_KEY)")
		publish = func(files []grc.File) error {
			key := os.Getenv("DRATA_API_KEY")
			if *ws == 0 || *ev == 0 || key == "" {
				return errors.New("publish drata needs --workspace-id, --evidence-id and DRATA_API_KEY")
			}
			return grc.NewDrata(key).Publish(*ws, *ev, files)
		}
	default:
		return fmt.Errorf("unknown publish target %q (want vanta or drata)", target)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	files, err := evidenceFiles(*dir)
	if err != nil {
		return err
	}
	if err := publish(files); err != nil {
		return err
	}
	fmt.Printf("tfproof: published %d files from %s to %s\n", len(files), *dir, target)
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
