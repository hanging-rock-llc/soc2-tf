// Package verify checks that the plan about to be applied is the plan that
// was reviewed and approved.
package verify

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hanging-rock-llc/soc2-tf/internal/ci"
	"github.com/hanging-rock-llc/soc2-tf/internal/plan"
	"github.com/hanging-rock-llc/soc2-tf/internal/record"
	"github.com/hanging-rock-llc/soc2-tf/internal/sink"
)

// Input describes the plan being applied.
type Input struct {
	Repo     string
	RunID    string
	Unit     string      // record.UnitKey of the root module instance
	FileHash string      // SHA-256 of the binary plan file being applied ("" if unknown)
	Facts    *plan.Facts // parsed plan being applied
	PR       int         // pull request to compare against (0 = skip)
	// PRHeadSHA is the head commit the pull request was merged at. When set,
	// the PR plan must have been captured on exactly that commit.
	PRHeadSHA string
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

// sameChanges reports whether the plan being applied would produce the same
// resources, actions and resulting values as a recorded plan.
func sameChanges(f *plan.Facts, rec *record.PlanEvidence) bool {
	return f.ValuesDigest == rec.ValuesDigest
}

// Check runs every applicable check. It never returns an error for a
// mismatch; mismatches are reported in the Verification so they are recorded
// as evidence. Errors are reserved for being unable to check at all.
func Check(s sink.Sink, in Input) (*record.Verification, error) {
	v := &record.Verification{Checked: true, Passed: true}
	note := func(format string, a ...any) { v.Notes = append(v.Notes, fmt.Sprintf(format, a...)) }

	runRec, err := load(s, record.RunIndexKey(in.Repo, in.RunID, in.Unit))
	switch {
	case errors.Is(err, sink.ErrNotFound):
		if in.RequireSameRun {
			v.Passed = false
			note("no plan was captured earlier in this run for this unit")
		}
	case err != nil:
		return nil, err
	default:
		v.SameRunRecord = runRec.ID
		match := false
		switch {
		case runRec.Plan == nil:
			note("the plan record from earlier in this run has no plan")
		case in.FileHash != "" && runRec.Plan.FileSHA256 != "":
			match = in.FileHash == runRec.Plan.FileSHA256
			if !match {
				note("plan file differs from the plan captured earlier in this run")
			}
		case in.Facts != nil:
			match = sameChanges(in.Facts, runRec.Plan)
			note("same-run check compared plan contents (no plan file hash available)")
			if !match {
				note("planned changes differ from the plan captured earlier in this run")
			}
		default:
			note("nothing to compare with the plan captured earlier in this run")
		}
		v.SameRun = boolp(match)
		if !match {
			v.Passed = false
		}
	}

	if in.PR > 0 {
		prRec, err := load(s, record.PRIndexKey(in.Repo, in.PR, in.Unit))
		if err == nil && prRec.Run.RunID == in.RunID {
			// A plan from this very run is the same-run plan, not evidence of
			// what was reviewed on the pull request.
			err = sink.ErrNotFound
		}
		switch {
		case errors.Is(err, sink.ErrNotFound):
			if in.RequirePR {
				v.Passed = false
			}
			note("no plan was captured on PR #%d for this unit", in.PR)
		case err != nil:
			return nil, err
		default:
			v.PullRequestRecord = prRec.ID
			match := true
			if !ci.PlansPREvent(prRec.Run.Provider, prRec.Run.Event) {
				match = false
				note("the PR #%d plan record was captured on a %q event, not one that plans the pull/merge request", in.PR, prRec.Run.Event)
			}
			switch {
			case in.PRHeadSHA == "":
				note("PR #%d merge head unknown; could not confirm its plan was taken on the final commit", in.PR)
			case prRec.Run.PRHeadSHA != in.PRHeadSHA:
				match = false
				note("the last plan on PR #%d was of commit %s, but the PR was merged at %s", in.PR, orUnknown(prRec.Run.PRHeadSHA), in.PRHeadSHA)
			}
			if in.Facts == nil || prRec.Plan == nil {
				match = false
				note("no plan contents to compare with PR #%d", in.PR)
			} else if !sameChanges(in.Facts, prRec.Plan) {
				match = false
				note("planned changes differ from the last plan reviewed on PR #%d", in.PR)
			}
			v.PullRequest = boolp(match)
			if !match {
				v.Passed = false
			}
		}
	}

	if v.SameRun == nil && v.PullRequest == nil {
		v.Passed = false
		note("nothing to verify against: no plan record found for this run or pull request")
	}
	return v, nil
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// Summary renders a one-line human summary.
func Summary(v *record.Verification) string {
	b, _ := json.Marshal(v)
	if v.Passed {
		return "verified: applied plan matches the reviewed plan " + string(b)
	}
	return "NOT verified: " + string(b)
}
