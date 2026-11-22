package record

import (
	"strings"
	"testing"
	"time"

	"github.com/hanging-rock-llc/soc2-tf/internal/ghctx"
)

func TestFinalizeAndVerify(t *testing.T) {
	r := &Record{
		Schema: Schema, Phase: PhasePlan, CapturedAt: time.Date(2026, 11, 22, 1, 2, 3, 456, time.UTC),
		Run:         ghctx.Run{Repository: "acme/infra", RunID: "1", RunAttempt: "1", Job: "plan"},
		IaC:         IaC{Binary: "tofu", Workdir: "envs/prod"},
		PullRequest: &ghctx.PR{Number: 1, Title: "Fix <script> & other \"things\""},
	}
	r.ID = NewID(r.Run, r.Phase, r.IaC.Workdir)
	b, err := Finalize(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `\u003c`) {
		t.Fatal("record should not HTML-escape (breaks jq re-verification)")
	}
	if _, ok, err := VerifyContent(b); err != nil || !ok {
		t.Fatalf("fresh record should verify: ok=%v err=%v", ok, err)
	}
	tampered := strings.Replace(string(b), "envs/prod", "envs/dev", 1)
	if _, ok, _ := VerifyContent([]byte(tampered)); ok {
		t.Fatal("tampered record should not verify")
	}
	if got := Key(r); got != "records/acme/infra/2026/11/22/1-1-plan-plan-envs__prod.json" {
		t.Fatalf("Key = %s", got)
	}
}

func TestWorkdirKey(t *testing.T) {
	cases := map[string]string{
		".":              "root",
		"":               "root",
		"./infra/prod/":  "infra__prod",
		"../escape":      "escape",
		"envs/us east 1": "envs__us-east-1",
		`envs\windows`:   "envs__windows",
	}
	for in, want := range cases {
		if got := WorkdirKey(in); got != want {
			t.Errorf("WorkdirKey(%q) = %q, want %q", in, got, want)
		}
	}
}
