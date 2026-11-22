package plan

import "testing"

const samplePlan = `{
  "format_version": "1.2",
  "terraform_version": "1.10.5",
  "resource_changes": [
    {"address": "aws_s3_bucket.logs", "change": {"actions": ["create"]}},
    {"address": "aws_iam_role.ci", "change": {"actions": ["update"]}},
    {"address": "aws_instance.web", "change": {"actions": ["delete", "create"]}},
    {"address": "aws_sqs_queue.old", "change": {"actions": ["delete"]}},
    {"address": "data.aws_caller_identity.me", "change": {"actions": ["read"]}},
    {"address": "aws_vpc.main", "change": {"actions": ["no-op"]}},
    {"address": "aws_route53_zone.legacy", "change": {"actions": ["no-op"], "importing": {"id": "Z123"}}}
  ],
  "output_changes": {
    "bucket": {"actions": ["create"]},
    "vpc_id": {"actions": ["no-op"]}
  }
}`

func TestParse(t *testing.T) {
	f, err := Parse([]byte(samplePlan))
	if err != nil {
		t.Fatal(err)
	}
	s := f.Summary
	if s.Create != 1 || s.Update != 1 || s.Replace != 1 || s.Delete != 1 || s.Read != 1 || s.NoOp != 1 || s.Import != 1 {
		t.Fatalf("unexpected summary: %+v", s)
	}
	if !f.HasChanges {
		t.Fatal("expected HasChanges")
	}
	// 6 resource changes (no-op excluded, import kept) + 1 output change
	if len(f.Changes) != 7 {
		t.Fatalf("expected 7 changes, got %d: %+v", len(f.Changes), f.Changes)
	}
	if f.TerraformVersion != "1.10.5" || f.JSONSHA256 == "" || f.ChangesetDigest == "" {
		t.Fatalf("missing metadata: %+v", f)
	}
}

func TestDigestIgnoresOrderAndReads(t *testing.T) {
	a := []Change{
		{Kind: "resource", Address: "b", Action: "create"},
		{Kind: "resource", Address: "a", Action: "update"},
		{Kind: "resource", Address: "data.x", Action: "read"},
	}
	b := []Change{
		{Kind: "resource", Address: "a", Action: "update"},
		{Kind: "resource", Address: "b", Action: "create"},
	}
	if Digest(a) != Digest(b) {
		t.Fatal("digest should be order-independent and ignore reads")
	}
	c := []Change{
		{Kind: "resource", Address: "a", Action: "replace"},
		{Kind: "resource", Address: "b", Action: "create"},
	}
	if Digest(a) == Digest(c) {
		t.Fatal("digest should change when an action changes")
	}
}

func TestNoChanges(t *testing.T) {
	f, err := Parse([]byte(`{"format_version":"1.2","resource_changes":[{"address":"x","change":{"actions":["no-op"]}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if f.HasChanges || len(f.Changes) != 0 {
		t.Fatalf("expected no changes: %+v", f)
	}
}

func TestParseRejectsNonPlan(t *testing.T) {
	if _, err := Parse([]byte(`{"hello":"world"}`)); err == nil {
		t.Fatal("expected error for non-plan JSON")
	}
}

func TestNormalize(t *testing.T) {
	cases := map[string][]string{
		"replace": {"create", "delete"},
		"no-op":   {"no-op"},
		"forget":  {"forget"},
	}
	for want, in := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%v)=%s want %s", in, got, want)
		}
	}
}
