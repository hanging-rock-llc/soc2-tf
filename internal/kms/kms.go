// Package kms signs record digests with an AWS KMS asymmetric key and fetches
// the matching public key, using the standard library and the awsv4 signer.
// Signatures are ECDSA_SHA_256 over a SHA-256 digest, so anyone holding the
// public key can verify a record offline (e.g. with openssl).
package kms

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hanging-rock-llc/soc2-tf/internal/awsv4"
	"github.com/hanging-rock-llc/soc2-tf/internal/httpretry"
)

// Algorithm is the KMS signing algorithm tfproof uses. Keys must be
// ECC_NIST_P256 with key usage SIGN_VERIFY.
const Algorithm = "ECDSA_SHA_256"

// Client calls KMS in one region.
type Client struct {
	Region string
	Creds  awsv4.Credentials
	// Endpoint overrides https://kms.<region>.amazonaws.com/ (tests, VPC
	// endpoints). Taken from TFPROOF_KMS_ENDPOINT when empty.
	Endpoint string
	HTTP     *http.Client
}

// New builds a client from environment credentials.
func New(region string) (*Client, error) {
	creds, err := awsv4.FromEnv()
	if err != nil {
		return nil, err
	}
	if region == "" {
		region = awsv4.Region()
	}
	if region == "" {
		return nil, errors.New("kms: no region (set AWS_REGION or --region)")
	}
	return &Client{Region: region, Creds: creds, Endpoint: os.Getenv("TFPROOF_KMS_ENDPOINT"), HTTP: &http.Client{Timeout: 30 * time.Second}}, nil
}

func (c *Client) call(target string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://kms.%s.amazonaws.com/", c.Region)
	}
	resp, err := httpretry.Do(c.HTTP, func() (*http.Request, error) {
		req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-amz-json-1.1")
		req.Header.Set("X-Amz-Target", "TrentService."+target)
		awsv4.Sign(req, c.Creds, c.Region, "kms", awsv4.HashHex(body), time.Now())
		return req, nil
	})
	if err != nil {
		return fmt.Errorf("kms %s: %w", target, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("kms %s: %w", target, err)
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("kms %s: %s: %s", target, resp.Status, strings.TrimSpace(string(b)))
	}
	return json.Unmarshal(b, out)
}

// SignDigest signs a SHA-256 digest. It returns the DER-encoded ECDSA
// signature and the key's ARN (KMS resolves aliases and IDs to it).
func (c *Client) SignDigest(keyID string, digest [32]byte) (sig []byte, keyARN string, err error) {
	var out struct {
		KeyID     string `json:"KeyId"`
		Signature []byte `json:"Signature"` // base64 in JSON
	}
	err = c.call("Sign", map[string]string{
		"KeyId":            keyID,
		"Message":          base64.StdEncoding.EncodeToString(digest[:]),
		"MessageType":      "DIGEST",
		"SigningAlgorithm": Algorithm,
	}, &out)
	if err != nil {
		return nil, "", err
	}
	if len(out.Signature) == 0 || out.KeyID == "" {
		return nil, "", errors.New("kms Sign: empty signature or key ID in response")
	}
	return out.Signature, out.KeyID, nil
}

// PublicKey fetches a signing key's public half and its ARN.
func (c *Client) PublicKey(keyID string) (*ecdsa.PublicKey, string, error) {
	var out struct {
		KeyID     string `json:"KeyId"`
		PublicKey []byte `json:"PublicKey"` // base64 DER SubjectPublicKeyInfo
		KeySpec   string `json:"KeySpec"`
		KeyUsage  string `json:"KeyUsage"`
	}
	if err := c.call("GetPublicKey", map[string]string{"KeyId": keyID}, &out); err != nil {
		return nil, "", err
	}
	if out.KeySpec != "ECC_NIST_P256" || out.KeyUsage != "SIGN_VERIFY" {
		return nil, "", fmt.Errorf("kms key %s is %s/%s; tfproof needs an ECC_NIST_P256 SIGN_VERIFY key", out.KeyID, out.KeySpec, out.KeyUsage)
	}
	pub, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return nil, "", fmt.Errorf("kms key %s: parse public key: %w", out.KeyID, err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, "", fmt.Errorf("kms key %s: not an ECDSA key", out.KeyID)
	}
	return ec, out.KeyID, nil
}
