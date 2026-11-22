package awsv4

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

var exampleCreds = Credentials{
	AccessKeyID:     "AKIDEXAMPLE",
	SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
}

var exampleTime = time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)

const emptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// The IAM ListUsers example from the AWS SigV4 documentation.
func TestSignIAMDocExample(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	Sign(req, exampleCreds, "us-east-1", "iam", emptyHash, exampleTime)

	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, " +
		"SignedHeaders=content-type;host;x-amz-date, " +
		"Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("Authorization mismatch\n got: %s\nwant: %s", got, want)
	}
}

// get-vanilla from the AWS SigV4 test suite.
func TestSignGetVanilla(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.amazonaws.com/", nil)
	Sign(req, exampleCreds, "us-east-1", "service", emptyHash, exampleTime)
	got := req.Header.Get("Authorization")
	if !strings.HasSuffix(got, "Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31") {
		t.Fatalf("unexpected signature: %s", got)
	}
}

func TestSessionTokenIsSigned(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.amazonaws.com/", nil)
	c := exampleCreds
	c.SessionToken = "tok"
	Sign(req, c, "us-east-1", "service", emptyHash, exampleTime)
	if req.Header.Get("X-Amz-Security-Token") != "tok" {
		t.Fatal("session token header missing")
	}
	if !strings.Contains(req.Header.Get("Authorization"), "x-amz-security-token") {
		t.Fatal("session token not in signed headers")
	}
}

func TestURIEncode(t *testing.T) {
	cases := map[string]string{
		"a b/c~d":   "a%20b/c~d",
		"ü":         "%C3%BC",
		"key=v&x+y": "key%3Dv%26x%2By",
	}
	for in, want := range cases {
		if got := URIEncode(in, false); got != want {
			t.Errorf("URIEncode(%q) = %q, want %q", in, got, want)
		}
	}
	if got := URIEncode("a/b", true); got != "a%2Fb" {
		t.Errorf("encodeSlash: got %q", got)
	}
}
