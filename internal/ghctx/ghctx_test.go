package ghctx

import (
	"testing"
	"time"
)

func at(h int) time.Time { return time.Date(2026, 11, 20, h, 0, 0, 0, time.UTC) }

func TestEvaluateLatestReviewWins(t *testing.T) {
	pr := &PR{Author: "alice", HeadSHA: "head"}
	reviews := []Review{
		{User: "bob", State: "APPROVED", CommitID: "old", SubmittedAt: at(9)},
		{User: "bob", State: "CHANGES_REQUESTED", CommitID: "head", SubmittedAt: at(10)},
		{User: "carol", State: "APPROVED", CommitID: "old", SubmittedAt: at(11)},
		{User: "carol", State: "COMMENTED", CommitID: "head", SubmittedAt: at(12)},
	}
	a := Evaluate(pr, reviews, nil, "alice")
	if len(a.ApprovedBy) != 1 || a.ApprovedBy[0] != "carol" {
		t.Fatalf("approved_by = %v, want [carol]", a.ApprovedBy)
	}
	if a.ApprovedHead {
		t.Fatal("carol approved an older commit; approved_head should be false")
	}
	if !a.IndependentApprover {
		t.Fatal("carol is independent of alice")
	}
}

func TestEvaluateSelfApprovalIsNotIndependent(t *testing.T) {
	a := Evaluate(nil, nil, []EnvApproval{{User: "alice", State: "approved"}}, "alice")
	if a.IndependentApprover {
		t.Fatal("actor approving their own dispatch run is not independent")
	}
	a = Evaluate(nil, nil, []EnvApproval{{User: "bob", State: "approved"}, {User: "eve", State: "rejected"}}, "alice")
	if !a.IndependentApprover || len(a.EnvironmentApprovedBy) != 1 {
		t.Fatalf("unexpected: %+v", a)
	}
}
