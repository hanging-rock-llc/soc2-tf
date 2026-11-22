package ci

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
		{User: "carol", State: "APPROVED", CommitID: "head", SubmittedAt: at(11)},
		{User: "carol", State: "COMMENTED", CommitID: "head", SubmittedAt: at(12)},
	}
	a := Evaluate(ApprovalInput{PR: pr, Reviews: reviews, Actor: "alice"})
	if len(a.ApprovedBy) != 1 || a.ApprovedBy[0] != "carol" {
		t.Fatalf("approved_by = %v, want [carol]", a.ApprovedBy)
	}
	if !a.ApprovedHead || !a.IndependentApprover || a.StaleApproval {
		t.Fatalf("carol independently approved the head commit: %+v", a)
	}
}

func TestEvaluateSelfApprovalIsNotIndependent(t *testing.T) {
	a := Evaluate(ApprovalInput{EnvApprovals: []EnvApproval{{User: "alice", State: "approved"}}, Actor: "alice"})
	if a.IndependentApprover {
		t.Fatal("actor approving their own dispatch run is not independent")
	}
	a = Evaluate(ApprovalInput{EnvApprovals: []EnvApproval{{User: "bob", State: "approved"}, {User: "eve", State: "rejected"}}, Actor: "alice"})
	if !a.IndependentApprover || len(a.EnvironmentApprovedBy) != 1 {
		t.Fatalf("unexpected: %+v", a)
	}
}

// bob approved an earlier commit; alice pushed more and approved her own
// deployment. Nobody independent approved what was deployed.
func TestEvaluateStaleApprovalPlusSelfEnvApproval(t *testing.T) {
	a := Evaluate(ApprovalInput{
		PR:           &PR{Author: "alice", HeadSHA: "h2"},
		Reviews:      []Review{{User: "bob", State: "APPROVED", CommitID: "h1", SubmittedAt: at(9)}},
		EnvApprovals: []EnvApproval{{User: "alice", State: "approved", Environments: []string{"production"}}},
		Environment:  "production",
		Actor:        "alice",
	})
	if a.IndependentApprover || !a.StaleApproval {
		t.Fatalf("stale approval plus self-approved deploy must not count as independent: %+v", a)
	}
	// An independent environment approval covers the final commit.
	a = Evaluate(ApprovalInput{
		PR:           &PR{Author: "alice", HeadSHA: "h2"},
		Reviews:      []Review{{User: "bob", State: "APPROVED", CommitID: "h1", SubmittedAt: at(9)}},
		EnvApprovals: []EnvApproval{{User: "dave", State: "approved", Environments: []string{"production"}}},
		Environment:  "production",
	})
	if !a.IndependentApprover || a.StaleApproval {
		t.Fatalf("dave's deployment approval is independent: %+v", a)
	}
}

func TestEvaluateOnlyCountsRecordedEnvironment(t *testing.T) {
	a := Evaluate(ApprovalInput{
		PR:           &PR{Author: "alice", HeadSHA: "h"},
		EnvApprovals: []EnvApproval{{User: "dave", State: "approved", Environments: []string{"staging"}}},
		Environment:  "production",
	})
	if a.IndependentApprover || len(a.EnvironmentApprovedBy) != 0 {
		t.Fatalf("a staging approval must not approve a production apply: %+v", a)
	}
}

func TestEvaluateCommitAuthorsAndBotsAreNotIndependent(t *testing.T) {
	a := Evaluate(ApprovalInput{
		PR: &PR{Author: "alice", HeadSHA: "h"},
		Reviews: []Review{
			{User: "bob", State: "APPROVED", CommitID: "h", SubmittedAt: at(9)},
			{User: "renovate[bot]", State: "APPROVED", CommitID: "h", SubmittedAt: at(9)},
		},
		CommitAuthors: []string{"alice", "bob"},
	})
	if a.IndependentApprover {
		t.Fatalf("bob pushed commits and the other approver is a bot: %+v", a)
	}
	if len(a.ChangeAuthors) != 2 {
		t.Fatalf("change_authors = %v", a.ChangeAuthors)
	}
}
