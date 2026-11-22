package report

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/hanging-rock-llc/soc2-tf/internal/awsv4"
	"github.com/hanging-rock-llc/soc2-tf/internal/ci"
	"github.com/hanging-rock-llc/soc2-tf/internal/cloudtrail"
	"github.com/hanging-rock-llc/soc2-tf/internal/plan"
	"github.com/hanging-rock-llc/soc2-tf/internal/record"
	"github.com/hanging-rock-llc/soc2-tf/internal/sink"
)

var capturedAt = time.Date(2026, 11, 20, 15, 0, 0, 0, time.UTC)

type keys map[string]*ecdsa.PrivateKey // ARN -> key

func (k keys) PublicKey(id string) (*ecdsa.PublicKey, string, error) {
	return &k[id].PublicKey, id, nil
}

// storeApply writes an apply record and, if signer is set, its signature.
func storeApply(t *testing.T, s sink.Sink, runID string, signer *ecdsa.PrivateKey, signerARN string) string {
	t.Helper()
	r := &record.Record{
		Schema: record.Schema, Phase: record.PhaseApply, CapturedAt: capturedAt,
		Run:           ci.Run{Provider: "github-actions", Repository: "acme/infra", RunID: runID, RunAttempt: "1", Job: "apply"},
		IaC:           record.IaC{Workdir: "infra/prod"},
		Plan:          &record.PlanEvidence{Facts: plan.Facts{HasChanges: true}},
		Apply:         &record.ApplyEvidence{Succeeded: true},
		CloudIdentity: &awsv4.Identity{Account: "123456789012", ARN: "arn:aws:sts::123456789012:assumed-role/tf-apply/gha-" + runID + "-1", RoleSessionName: "gha-" + runID + "-1"},
	}
	r.ID = record.NewID(r.Run, r.Phase, record.UnitKey(r.IaC))
	b, err := record.Finalize(r)
	if err != nil {
		t.Fatal(err)
	}
	key := record.Key(r)
	if err := s.Create(key, b, ""); err != nil {
		t.Fatal(err)
	}
	if signer != nil {
		sum := sha256.Sum256(b)
		der, _ := ecdsa.SignASN1(rand.Reader, signer, sum[:])
		sb, _ := json.Marshal(record.NewSignature(b, "ECDSA_SHA_256", signerARN, der))
		if err := s.Create(record.SignatureKey(key), sb, ""); err != nil {
			t.Fatal(err)
		}
	}
	return key
}

func TestSignatureChecks(t *testing.T) {
	applyKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	planKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	const applyARN, planARN = "arn:aws:kms:us-east-1:1:key/apply", "arn:aws:kms:us-east-1:1:key/plan"
	s := &sink.Dir{Root: t.TempDir()}
	storeApply(t, s, "100", applyKey, applyARN)
	storeApply(t, s, "200", nil, "")
	storeApply(t, s, "300", planKey, planARN) // plan role's key on an apply record
	tampered := storeApply(t, s, "400", applyKey, applyARN)
	var sig record.Signature
	b, _ := s.Get(record.SignatureKey(tampered))
	json.Unmarshal(b, &sig)
	sig.Signature[len(sig.Signature)-1] ^= 0xff
	b, _ = json.Marshal(sig)
	s.Put(record.SignatureKey(tampered), b, "")

	res, err := Build(s, Options{
		Since:       capturedAt.Add(-time.Hour),
		SigningKeys: map[record.Phase]string{record.PhaseApply: applyARN},
		Keys:        keys{applyARN: applyKey, planARN: planKey},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"100": "", "200": "record not signed", "300": "signed by unexpected key " + planARN, "400": "signature invalid"}
	for _, row := range res.Applies {
		ex := strings.Join(row.Exceptions, "; ")
		w := want[row.Rec.Run.RunID]
		if (w == "" && strings.Contains(ex, "sign")) || (w != "" && !strings.Contains(ex, w)) {
			t.Errorf("run %s: exceptions %q, want %q", row.Rec.Run.RunID, ex, w)
		}
	}
}

type fakeTrail struct{ got []cloudtrail.Query }

func (f *fakeTrail) Lookup(qs []cloudtrail.Query) ([][]cloudtrail.Event, error) {
	f.got = qs
	out := make([][]cloudtrail.Event, len(qs))
	out[0] = []cloudtrail.Event{
		{Time: capturedAt.Add(-time.Minute), Source: "ec2.amazonaws.com", Name: "RunInstances", EventID: "e1"},
		{Time: capturedAt.Add(-time.Minute), Source: "iam.amazonaws.com", Name: "PutRolePolicy", ErrorCode: "AccessDenied", EventID: "e2"},
	}
	return out, nil
}

func TestJoinCloudTrail(t *testing.T) {
	s := &sink.Dir{Root: t.TempDir()}
	storeApply(t, s, "100", nil, "")
	res, err := Build(s, Options{Since: capturedAt.Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	trail := &fakeTrail{}
	if err := res.JoinCloudTrail(trail, 90*time.Minute); err != nil {
		t.Fatal(err)
	}
	q := trail.got[0]
	if q.SessionARN != "arn:aws:sts::123456789012:assumed-role/tf-apply/gha-100-1" || q.Account != "123456789012" || !q.To.Equal(capturedAt) || !q.From.Equal(capturedAt.Add(-90*time.Minute)) {
		t.Fatalf("query = %+v", q)
	}
	var buf bytes.Buffer
	res.WriteCSV(&buf)
	rows, _ := csv.NewReader(&buf).ReadAll()
	col := func(name string) string {
		for i, h := range rows[0] {
			if h == name {
				return rows[1][i]
			}
		}
		return "missing"
	}
	if col("aws_api_calls") != "2" || col("aws_api_errors") != "1" {
		t.Fatalf("calls=%s errors=%s", col("aws_api_calls"), col("aws_api_errors"))
	}
	buf.Reset()
	res.WriteAPICalls(&buf)
	if !strings.Contains(buf.String(), "PutRolePolicy") || !strings.Contains(buf.String(), "AccessDenied") {
		t.Fatalf("api-calls.csv:\n%s", buf.String())
	}
}
