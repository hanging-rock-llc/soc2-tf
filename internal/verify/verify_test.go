package verify

import (
	"strings"
	"testing"
	"time"

	"github.com/hanging-rock-llc/soc2-tf/internal/ghctx"
	"github.com/hanging-rock-llc/soc2-tf/internal/plan"
	"github.com/hanging-rock-llc/soc2-tf/internal/record"
	"github.com/hanging-rock-llc/soc2-tf/internal/sink"
)

const unit = "infra__prod"

func facts(t *testing.T, cidr string) *plan.Facts {
	t.Helper()
	f, err := plan.Parse([]byte(`{"format_version":"1.2","resource_changes":[{"address":"aws_security_group_rule.in","change":{"actions":["update"],"after":{"cidr":"` + cidr + `"}}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// storePR writes a PR index record captured by run runID on the given event
// at PR head commit head.
func storePR(t *testing.T, s sink.Sink, runID, event, head string, f *plan.Facts) {
	t.Helper()
	r := &record.Record{
		Schema: record.Schema, Phase: record.PhasePlan, CapturedAt: time.Now().UTC(),
		Run:  ghctx.Run{Repository: "acme/infra", RunID: runID, RunAttempt: "1", Event: event, PRHeadSHA: head},
		Plan: &record.PlanEvidence{Facts: *f},
	}
	r.ID = record.NewID(r.Run, r.Phase, unit)
	b, err := record.Finalize(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(record.PRIndexKey("acme/infra", 7, unit), b, ""); err != nil {
		t.Fatal(err)
	}
}

func TestPRCheck(t *testing.T) {
	reviewed := facts(t, "10.0.0.0/16")
	cases := []struct {
		name            string
		runID, event    string
		head, mergeHead string
		applied         *plan.Facts
		wantPass        bool
		wantNote        string
	}{
		{"matches reviewed plan at merge head", "444", "pull_request", "h2", "h2", reviewed, true, ""},
		{"different planned values", "444", "pull_request", "h2", "h2", facts(t, "0.0.0.0/0"), false, "planned changes differ"},
		{"plan of an earlier PR commit", "444", "pull_request", "h1", "h2", reviewed, false, "was of commit h1"},
		{"record from a push run", "444", "push", "", "h2", reviewed, false, `"push" event`},
		{"record from this run is not PR evidence", "555", "pull_request", "h2", "h2", reviewed, false, "no plan was captured on PR #7"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &sink.Dir{Root: t.TempDir()}
			storePR(t, s, c.runID, c.event, c.head, reviewed)
			v, err := Check(s, Input{Repo: "acme/infra", RunID: "555", Unit: unit, Facts: c.applied, PR: 7, PRHeadSHA: c.mergeHead, RequirePR: true})
			if err != nil {
				t.Fatal(err)
			}
			if v.Passed != c.wantPass {
				t.Fatalf("passed=%v want %v; notes=%v", v.Passed, c.wantPass, v.Notes)
			}
			if c.wantNote != "" && !strings.Contains(strings.Join(v.Notes, "; "), c.wantNote) {
				t.Fatalf("notes %v missing %q", v.Notes, c.wantNote)
			}
		})
	}
}
