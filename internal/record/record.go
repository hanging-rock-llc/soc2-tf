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

// IaC describes the Terraform/OpenTofu root module.
type IaC struct {
	Binary  string `json:"binary"`
	Version string `json:"version,omitempty"`
	Workdir string `json:"workdir"`
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
	w = strings.ReplaceAll(w, "/", "__")
	var b strings.Builder
	for _, c := range w {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
			b.WriteRune(c)
		} else {
			b.WriteByte('-')
		}
	}
	return b.String()
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

// NewID builds the record ID: <run_id>-<attempt>-<job>-<phase>-<workdir>.
func NewID(run ghctx.Run, phase Phase, workdir string) string {
	job := run.Job
	if job == "" {
		job = "job"
	}
	return fmt.Sprintf("%s-%s-%s-%s-%s", run.RunID, run.RunAttempt, safe(job), phase, WorkdirKey(workdir))
}

// Key is the record's object key (relative to the sink prefix):
// records/<owner>/<repo>/<yyyy>/<mm>/<dd>/<id>.json
func Key(r *Record) string {
	t := r.CapturedAt.UTC()
	return path.Join("records", r.Run.Repository, t.Format("2006"), t.Format("01"), t.Format("02"), r.ID+".json")
}

// RunIndexKey points at the latest plan record for a workdir in a run.
func RunIndexKey(repo, runID, workdir string) string {
	return path.Join("index", repo, "run", runID, WorkdirKey(workdir), "plan.json")
}

// PRIndexKey points at the latest plan record for a workdir on a PR.
func PRIndexKey(repo string, pr int, workdir string) string {
	return path.Join("index", repo, "pr", fmt.Sprint(pr), WorkdirKey(workdir), "plan.json")
}

// compact encodes v as compact JSON without HTML escaping, so the bytes
// match what `jq -c` produces and a record can be re-verified with standard
// tools (see docs/record-schema.md).
func compact(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// Finalize sets ContentSHA256 and returns the serialized record.
func Finalize(r *Record) ([]byte, error) {
	r.ContentSHA256 = ""
	b, err := compact(r)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	r.ContentSHA256 = hex.EncodeToString(sum[:])
	out, err := compact(r)
	if err != nil {
		return nil, err
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, out, "", "  "); err != nil {
		return nil, err
	}
	return pretty.Bytes(), nil
}

// VerifyContent recomputes ContentSHA256 for a stored record.
func VerifyContent(data []byte) (*Record, bool, error) {
	var r Record
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, false, err
	}
	want := r.ContentSHA256
	cp := r
	cp.ContentSHA256 = ""
	b, err := compact(&cp)
	if err != nil {
		return nil, false, err
	}
	sum := sha256.Sum256(b)
	return &r, hex.EncodeToString(sum[:]) == want, nil
}
