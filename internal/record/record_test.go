package record

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/hanging-rock-llc/soc2-tf/internal/ci"
)

func sample() *Record {
	r := &Record{
		Schema: Schema, Phase: PhasePlan, CapturedAt: time.Date(2026, 11, 22, 1, 2, 3, 456, time.UTC),
		Run:         ci.Run{Repository: "acme/infra", RunID: "1", RunAttempt: "1", Job: "plan"},
		IaC:         IaC{Binary: "tofu", Workdir: "envs/prod"},
		PullRequest: &ci.PR{Number: 1, Title: "Fix <script> & other \"things\" \u2028"},
	}
	r.ID = NewID(r.Run, r.Phase, UnitKey(r.IaC))
	return r
}

func TestFinalizeAndVerify(t *testing.T) {
	r := sample()
	b, err := Finalize(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `\u003c`) {
		t.Fatal("record should not HTML-escape")
	}
	if bytes.Count(b, []byte("\n")) != 1 || !bytes.HasSuffix(b, []byte("}\n")) {
		t.Fatal("record should be one line of JSON")
	}
	if _, ok, err := VerifyContent(b); err != nil || !ok {
		t.Fatalf("fresh record should verify: ok=%v err=%v", ok, err)
	}
	tampered := strings.Replace(string(b), "envs/prod", "envs/dev", 1)
	if _, ok, _ := VerifyContent([]byte(tampered)); ok {
		t.Fatal("tampered record should not verify")
	}
	if got := Key(r); got != "records/plan/acme/infra/2026/11/22/1-1-plan-plan-envs__prod.json" {
		t.Fatalf("Key = %s", got)
	}
}

func TestVerifyCoversFieldsUnknownToThisVersion(t *testing.T) {
	b, err := Finalize(sample())
	if err != nil {
		t.Fatal(err)
	}
	injected := bytes.Replace(b, []byte(`{"schema"`), []byte(`{"approved_by_auditor":true,"schema"`), 1)
	if _, ok, _ := VerifyContent(injected); ok {
		t.Fatal("adding a field the struct doesn't know about must break the hash")
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

func TestUnitKeySeparatesWorkspacesAndStacks(t *testing.T) {
	cases := []struct {
		iac  IaC
		want string
	}{
		{IaC{Workdir: "infra/prod"}, "infra__prod"},
		{IaC{Workdir: "infra/prod", Workspace: "default"}, "infra__prod"},
		{IaC{Workdir: "infra/prod", Workspace: "staging"}, "infra__prod@staging"},
		{IaC{Workdir: "infra/prod", Workspace: "default x"}, "infra__prod@default-x"},
		{IaC{Workdir: "infra/prod", Stack: "prod-eu"}, "prod-eu"},
		{IaC{Workdir: "infra/prod", Stack: "prod-eu", Workspace: "blue"}, "prod-eu@blue"},
	}
	for _, c := range cases {
		if got := UnitKey(c.iac); got != c.want {
			t.Errorf("UnitKey(%+v) = %q, want %q", c.iac, got, c.want)
		}
	}
}
