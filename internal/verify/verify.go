// Package verify checks that the plan about to be applied is the plan that
// was reviewed and approved.
package verify

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hanging-rock-llc/soc2-tf/internal/plan"
	"github.com/hanging-rock-llc/soc2-tf/internal/record"
	"github.com/hanging-rock-llc/soc2-tf/internal/sink"
)

// Input describes the plan being applied.
type Input struct {
	Repo     string
	RunID    string
	Workdir  string
	FileHash string      // SHA-256 of the binary plan file being applied ("" if unknown)
	Facts    *plan.Facts // parsed plan being applied
	PR       int         // pull request to compare against (0 = skip)
	// RequireSameRun fails verification when no plan record exists for this
	// run (use for plan -> gate -> apply workflows).
	RequireSameRun bool
	// RequirePR fails verification when no PR plan record exists.
	RequirePR bool
}

func load(s sink.Sink, key string) (*record.Record, error) {
	b, err := s.Get(key)
	if err != nil {
		return nil, err
	}
	r, ok, err := record.VerifyContent(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", key, err)
	}
	if !ok {
		return nil, fmt.Errorf("%s: content hash mismatch; record may have been altered", key)
	}
	return r, nil
}

func boolp(b bool) *bool { return &b }

// Check runs every applicable check. It never returns an error for a
// mismatch; mismatches are reported in the Verification so they are recorded
// as evidence. Errors are reserved for being unable to check at all.
func Check(s sink.Sink, in Input) (*record.Verification, error) {
	v := &record.Verification{Checked: true, Passed: true}

	runRec, err := load(s, record.RunIndexKey(in.Repo, in.RunID, in.Workdir))
	switch {
	case errors.Is(err, sink.ErrNotFound):
		if in.RequireSameRun {
			v.Passed = false
			v.Notes = append(v.Notes, "no plan was captured earlier in this run for this workdir")
		}
	case err != nil:
		return nil, err
	default:
		v.SameRunRecord = runRec.ID
		match := false
		if in.FileHash != "" && runRec.Plan != nil && runRec.Plan.FileSHA256 != "" {
			match = in.FileHash == runRec.Plan.FileSHA256
			if !match {
				v.Notes = append(v.Notes, "plan file differs from the plan captured earlier in this run")
			}
		} else if in.Facts != nil && runRec.Plan != nil {
			match = in.Facts.ChangesetDigest == runRec.Plan.ChangesetDigest
			v.Notes = append(v.Notes, "same-run check used change-set digest (no plan file hash available)")
			if !match {
				v.Notes = append(v.Notes, "change set differs from the plan captured earlier in this run")
			}
		}
		v.SameRun = boolp(match)
		if !match {
			v.Passed = false
		}
	}

	if in.PR > 0 {
		prRec, err := load(s, record.PRIndexKey(in.Repo, in.PR, in.Workdir))
		switch {
		case errors.Is(err, sink.ErrNotFound):
			if in.RequirePR {
				v.Passed = false
			}
			v.Notes = append(v.Notes, fmt.Sprintf("no plan was captured on PR #%d for this workdir", in.PR))
		case err != nil:
			return nil, err
		default:
			v.PullRequestRecord = prRec.ID
			match := in.Facts != nil && prRec.Plan != nil && in.Facts.ChangesetDigest == prRec.Plan.ChangesetDigest
			v.PullRequest = boolp(match)
			if !match {
				v.Passed = false
				v.Notes = append(v.Notes, fmt.Sprintf("change set differs from the last plan reviewed on PR #%d", in.PR))
			}
		}
	}

	if v.SameRun == nil && v.PullRequest == nil {
		v.Passed = false
		v.Notes = append(v.Notes, "nothing to verify against: no plan record found for this run or pull request")
	}
	return v, nil
}

// Summary renders a one-line human summary.
func Summary(v *record.Verification) string {
	b, _ := json.Marshal(v)
	if v.Passed {
		return "verified: applied plan matches the reviewed plan " + string(b)
	}
	return "NOT verified: " + string(b)
}
