package grc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/hanging-rock-llc/soc2-tf/internal/httpretry"
)

// Vanta publishes tfproof's evidence files to a Vanta document via the
// Manage Vanta API (client_credentials OAuth app type). See:
//   - auth: https://developer.vanta.com/docs/concepts/authentication
//   - upload+submit: https://developer.vanta.com/docs/guides/upload-a-document
//   - upload reference: https://developer.vanta.com/api-reference/documents/upload-file-for-document
type Vanta struct {
	// BaseURL is the Manage Vanta API host. Defaults to
	// https://api.vanta.com; set TFPROOF_VANTA_API_URL to override (e.g.
	// https://api.vanta-gov.com for Vanta Gov).
	BaseURL      string
	ClientID     string
	ClientSecret string
	HTTP         *http.Client
}

// vantaScope is the exact scope string a Manage Vanta app must request to
// upload and submit document evidence. Vanta validates scopes at
// token-exchange time: missing vanta-api.all:write returns invalid_scope,
// and missing vanta-api.documents:upload returns a 403 on /uploads — both
// are easy to miss since they're separate from the general read/write
// scopes.
const vantaScope = "vanta-api.all:read vanta-api.all:write vanta-api.documents:upload"

// NewVanta constructs a client for the default (commercial) Manage Vanta API
// host, ready to have BaseURL or HTTP overridden before use.
func NewVanta(clientID, clientSecret string) *Vanta {
	baseURL := os.Getenv("TFPROOF_VANTA_API_URL")
	if baseURL == "" {
		baseURL = "https://api.vanta.com"
	}
	return &Vanta{
		BaseURL:      baseURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		HTTP:         &http.Client{Timeout: 60 * time.Second},
	}
}

func (v *Vanta) httpClient() *http.Client {
	if v.HTTP != nil {
		return v.HTTP
	}
	return http.DefaultClient
}

// Publish uploads each file to the document and submits it, so the
// document's evidence is current. Uploads land as drafts; the single submit
// call at the end flips the document's uploadStatus to OK and makes the
// just-uploaded files the canonical evidence auditors see.
func (v *Vanta) Publish(documentID, description string, files []File) error {
	token, err := v.token()
	if err != nil {
		return err
	}

	client := v.httpClient()
	for _, f := range files {
		if err := v.upload(client, token, documentID, description, f); err != nil {
			return err
		}
	}
	return v.submit(client, token, documentID)
}

// token mints a fresh Manage Vanta access token. Vanta allows only one
// active access_token per Application — minting a second immediately
// revokes the first — and client_credentials tokens carry no refresh token,
// so Publish mints its own token per call rather than caching one across a
// long-lived process.
func (v *Vanta) token() (string, error) {
	body, err := json.Marshal(struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		Scope        string `json:"scope"`
		GrantType    string `json:"grant_type"`
	}{
		ClientID:     v.ClientID,
		ClientSecret: v.ClientSecret,
		Scope:        vantaScope,
		GrantType:    "client_credentials",
	})
	if err != nil {
		return "", fmt.Errorf("vanta token request: %w", err)
	}

	resp, err := httpretry.Do(v.httpClient(), func() (*http.Request, error) {
		req, err := http.NewRequest(http.MethodPost, v.BaseURL+"/oauth/token", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		return req, nil
	})
	if err != nil {
		return "", fmt.Errorf("vanta token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("vanta token request: %s: %s", resp.Status, readErrorBody(resp))
	}

	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return "", fmt.Errorf("vanta token request: decoding response: %w", err)
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("vanta token request: response had no access_token")
	}
	return tok.AccessToken, nil
}

// upload attaches f to documentID as a draft evidence file via
// POST /v1/documents/{documentId}/uploads. Vanta documents evidence of any
// type under this endpoint (no accepted-extension allowlist like Drata's),
// so changes.csv and summary.md are sent as-is with their real Content-Type.
func (v *Vanta) upload(client *http.Client, token, documentID, description string, f File) error {
	body, contentType, err := encodeMultipart(
		multipartField{Name: "file", Filename: f.Name, ContentType: f.ContentType, Value: f.Data},
		multipartField{Name: "description", Value: []byte(description)},
	)
	if err != nil {
		return fmt.Errorf("vanta upload %s: %w", f.Name, err)
	}

	url := fmt.Sprintf("%s/v1/documents/%s/uploads", v.BaseURL, documentID)
	resp, err := httpretry.Do(client, func() (*http.Request, error) {
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		return req, nil
	})
	if err != nil {
		return fmt.Errorf("vanta upload %s: %w", f.Name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("vanta upload %s: %s: %s", f.Name, resp.Status, readErrorBody(resp))
	}
	io.Copy(io.Discard, resp.Body)
	return nil
}

// submit moves documentID from draft to OK via POST /v1/documents/{documentId}/submit.
func (v *Vanta) submit(client *http.Client, token, documentID string) error {
	url := fmt.Sprintf("%s/v1/documents/%s/submit", v.BaseURL, documentID)
	resp, err := httpretry.Do(client, func() (*http.Request, error) {
		req, err := http.NewRequest(http.MethodPost, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		return req, nil
	})
	if err != nil {
		return fmt.Errorf("vanta submit document %s: %w", documentID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("vanta submit document %s: %s: %s", documentID, resp.Status, readErrorBody(resp))
	}
	io.Copy(io.Discard, resp.Body)
	return nil
}
