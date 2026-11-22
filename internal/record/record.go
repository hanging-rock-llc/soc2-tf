// Package record defines the tfproof evidence record and where records live
// in the evidence store.
package record

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/hanging-rock-llc/soc2-tf/internal/awsv4"
	"github.com/hanging-rock-llc/soc2-tf/internal/ghctx"
	"github.com/hanging-rock-llc/soc2-tf/internal/plan"
)

// Schema is the record schema identifier. Bump on breaking changes.
const Schema = "tfproof.dev/record/v1"

// Phase is plan or apply.
type Phase string

const (
	PhasePlan  Phase = "plan"
	PhaseApply Phase = "apply"
)

// Tool identifies the producer.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// IaC describes the Terraform/OpenTofu root module instance.
type IaC struct {
	Binary  string `json:"binary"`
	Version string `json:"version,omitempty"`
	Workdir string `json:"workdir"`
	// Workspace is the selected Terraform/OpenTofu workspace ("" = default).
	Workspace string `json:"workspace,omitempty"`
	// Stack optionally names the unit explicitly (e.g. "prod-us-east-1") when
	// one workdir is planned several ways, such as with different var files.
	Stack string `json:"stack,omitempty"`
}

// PlanEvidence is what was proposed.
type PlanEvidence struct {
	FileSHA256 string `json:"file_sha256,omitempty"`
	plan.Facts
}

// Verification records whether an apply ran the plan that was reviewed.
type Verification struct {
	Checked bool `json:"checked"`
	// SameRun: the plan file applied is byte-identical to the plan captured
	// earlier in the same workflow run (plan job -> approval gate -> apply).
	SameRun       *bool  `json:"same_run_match,omitempty"`
	SameRunRecord string `json:"same_run_record,omitempty"`
	// PullRequest: the change set applied matches the last plan captured on
	// the pull request that was reviewed and merged.
	PullRequest       *bool    `json:"pull_request_match,omitempty"`
	PullRequestRecord string   `json:"pull_request_record,omitempty"`
	Passed            bool     `json:"passed"`
	Notes             []string `json:"notes,omitempty"`
}

// ApplyEvidence is what actually ran.
type ApplyEvidence struct {
	ExitCode     int           `json:"exit_code"`
	Succeeded    bool          `json:"succeeded"`
	LogSHA256    string        `json:"log_sha256,omitempty"`
	LogKey       string        `json:"log_key,omitempty"`
	Verification *Verification `json:"verification,omitempty"`
}

// Record is one immutable evidence record.
type Record struct {
	Schema        string          `json:"schema"`
	ID            string          `json:"id"`
	Phase         Phase           `json:"phase"`
	CapturedAt    time.Time       `json:"captured_at"`
	Tool          Tool            `json:"tool"`
	IaC           IaC             `json:"iac"`
	Run           ghctx.Run       `json:"run"`
	PullRequest   *ghctx.PR       `json:"pull_request,omitempty"`
	Approval      *ghctx.Approval `json:"approval,omitempty"`
	CloudIdentity *awsv4.Identity `json:"cloud_identity,omitempty"`
	Plan          *PlanEvidence   `json:"plan,omitempty"`
	Apply         *ApplyEvidence  `json:"apply,omitempty"`
	Warnings      []string        `json:"warnings,omitempty"`
	// ContentSHA256 is the SHA-256 of the record serialized with this field
	// empty. Together with S3's checksum and Object Lock, it lets anyone
	// re-verify a record has not been altered.
	ContentSHA256 string `json:"content_sha256"`
}

// WorkdirKey turns a workdir into a stable, path-safe token.
func WorkdirKey(workdir string) string {
	w := strings.Trim(path.Clean("/"+strings.ReplaceAll(workdir, "\\", "/")), "/")
	if w == "" {
		w = "root"
	}
	return safe(strings.ReplaceAll(w, "/", "__"))
}

func safe(s string) string {
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
			b.WriteRune(c)
		} else {
			b.WriteByte('-')
		}
	}
	return b.String()
}

// UnitKey identifies the root module instance a plan or apply belongs to:
// the stack name if set, else the workdir, plus "@<workspace>" for a
// non-default workspace. Plans of different units never match each other.
func UnitKey(iac IaC) string {
	k := WorkdirKey(iac.Workdir)
	if iac.Stack != "" {
		k = WorkdirKey(iac.Stack)
	}
	if iac.Workspace != "" && iac.Workspace != "default" {
		k += "@" + safe(iac.Workspace)
	}
	return k
}

// NewID builds the record ID: <run_id>-<attempt>-<job>-<phase>-<unit>.
func NewID(run ghctx.Run, phase Phase, unit string) string {
	job := run.Job
	if job == "" {
		job = "job"
	}
	return fmt.Sprintf("%s-%s-%s-%s-%s", run.RunID, run.RunAttempt, safe(job), phase, unit)
}

// Key is the record's object key (relative to the sink prefix):
// records/<phase>/<owner>/<repo>/<yyyy>/<mm>/<dd>/<id>.json
//
// The phase comes first so IAM can let the plan role write only plan records
// and the apply role only apply records.
func Key(r *Record) string {
	t := r.CapturedAt.UTC()
	return path.Join("records", string(r.Phase), r.Run.Repository, t.Format("2006"), t.Format("01"), t.Format("02"), r.ID+".json")
}

// RunIndexKey points at the latest plan record for a unit in a run.
func RunIndexKey(repo, runID, unit string) string {
	return path.Join("index", repo, "run", runID, unit, "plan.json")
}

// PRIndexKey points at the latest plan record for a unit on a PR.
func PRIndexKey(repo string, pr int, unit string) string {
	return path.Join("index", repo, "pr", fmt.Sprint(pr), unit, "plan.json")
}

// compact encodes v as compact JSON without HTML escaping.
func compact(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// hashField matches the content hash, which is always the last field.
var hashField = regexp.MustCompile(`"content_sha256":"[0-9a-f]*"}$`)

const blankHash = `"content_sha256":""}`

// Finalize sets ContentSHA256 and returns the serialized record: one line of
// compact JSON plus a newline. The hash covers exactly the stored bytes with
// the hash value blanked, so it can be re-checked with sed and sha256sum
// (see docs/record-schema.md).
func Finalize(r *Record) ([]byte, error) {
	r.ContentSHA256 = ""
	b, err := compact(r)
	if err != nil {
		return nil, err
	}
	if !bytes.HasSuffix(b, []byte(blankHash)) {
		return nil, fmt.Errorf("record: content_sha256 must be the last field")
	}
	sum := sha256.Sum256(b)
	r.ContentSHA256 = hex.EncodeToString(sum[:])
	out := append(bytes.TrimSuffix(b, []byte(blankHash)), []byte(`"content_sha256":"`+r.ContentSHA256+`"}`+"\n")...)
	return out, nil
}

// VerifyContent checks a stored record's content hash against its bytes as
// stored, so fields this version of tfproof doesn't know about are covered
// too. Records stored pretty-printed (tfproof before compact storage) are
// compacted first.
func VerifyContent(data []byte) (*Record, bool, error) {
	var r Record
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, false, err
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, data); err != nil {
		return nil, false, err
	}
	b := buf.Bytes()
	loc := hashField.FindIndex(b)
	if loc == nil {
		return &r, false, nil
	}
	blanked := append(append([]byte{}, b[:loc[0]]...), blankHash...)
	sum := sha256.Sum256(blanked)
	return &r, r.ContentSHA256 != "" && hex.EncodeToString(sum[:]) == r.ContentSHA256, nil
}
