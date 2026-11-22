package kms

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hanging-rock-llc/soc2-tf/internal/awsv4"
)

const keyARN = "arn:aws:kms:us-east-1:123456789012:key/1111-2222"

// fakeKMS signs with a real P-256 key the way KMS does: DER ECDSA over the
// digest it's given.
func fakeKMS(t *testing.T, priv *ecdsa.PrivateKey, keySpec string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/x-amz-json-1.1" || !strings.Contains(r.Header.Get("Authorization"), "/kms/aws4_request") {
			http.Error(w, "bad request headers", http.StatusBadRequest)
			return
		}
		var in map[string]string
		json.NewDecoder(r.Body).Decode(&in)
		switch r.Header.Get("X-Amz-Target") {
		case "TrentService.Sign":
			if in["MessageType"] != "DIGEST" || in["SigningAlgorithm"] != "ECDSA_SHA_256" {
				http.Error(w, `{"__type":"ValidationException"}`, http.StatusBadRequest)
				return
			}
			digest, _ := base64.StdEncoding.DecodeString(in["Message"])
			sig, _ := ecdsa.SignASN1(rand.Reader, priv, digest)
			json.NewEncoder(w).Encode(map[string]any{"KeyId": keyARN, "Signature": sig, "SigningAlgorithm": "ECDSA_SHA_256"})
		case "TrentService.GetPublicKey":
			der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
			json.NewEncoder(w).Encode(map[string]any{"KeyId": keyARN, "PublicKey": der, "KeySpec": keySpec, "KeyUsage": "SIGN_VERIFY"})
		default:
			http.Error(w, "unknown target", http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	return &Client{Region: "us-east-1", Creds: awsv4.Credentials{AccessKeyID: "AK", SecretAccessKey: "s"}, Endpoint: srv.URL}
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c := fakeKMS(t, priv, "ECC_NIST_P256")
	digest := sha256.Sum256([]byte(`{"id":"r1"}`))
	sig, arn, err := c.SignDigest("alias/tfproof-apply", digest)
	if err != nil || arn != keyARN {
		t.Fatalf("SignDigest: arn=%q err=%v", arn, err)
	}
	pub, arn, err := c.PublicKey("alias/tfproof-apply")
	if err != nil || arn != keyARN {
		t.Fatalf("PublicKey: arn=%q err=%v", arn, err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatal("signature from KMS does not verify with its public key")
	}
}

func TestPublicKeyRejectsWrongKeySpec(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c := fakeKMS(t, priv, "RSA_2048")
	if _, _, err := c.PublicKey("k"); err == nil || !strings.Contains(err.Error(), "ECC_NIST_P256") {
		t.Fatalf("want key-spec error, got %v", err)
	}
}
