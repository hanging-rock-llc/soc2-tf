package grc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/hanging-rock-llc/soc2-tf/internal/httpretry"
)

// Drata publishes tfproof's evidence files to a Drata Evidence item via the
// Public API v2. See:
//   - https://developers.drata.com/openapi/reference/v2/tag/Evidence
//   - https://developers.drata.com/openapi/reference/v2/tag/Uploads
//
// Drata authenticates with a long-lived API key sent as a bearer token (the
// API's documented "bearer" security scheme, bearerFormat API_KEY) — unlike
// Vanta there is no token to mint or refresh.
type Drata struct {
	// BaseURL is the Drata Public API v2 host plus path prefix. Defaults to
	// https://public-api.drata.com/public/v2 (US); set TFPROOF_DRATA_API_URL
	// for the EU (https://public-api.eu.drata.com/public/v2) or APAC
	// (https://public-api.apac.drata.com/public/v2) region instead.
	BaseURL string
	APIKey  string
	HTTP    *http.Client
}

// NewDrata constructs a client for the default (US) Drata Public API v2 host,
// ready to have BaseURL or HTTP overridden before use.
func NewDrata(apiKey string) *Drata {
	baseURL := os.Getenv("TFPROOF_DRATA_API_URL")
	if baseURL == "" {
		baseURL = "https://public-api.drata.com/public/v2"
	}
	return &Drata{
		BaseURL: baseURL,
		APIKey:  apiKey,
		HTTP:    &http.Client{Timeout: 60 * time.Second},
	}
}

func (d *Drata) httpClient() *http.Client {
	if d.HTTP != nil {
		return d.HTTP
	}
	return http.DefaultClient
}

// uploaded pairs an uploaded File with the fileKey Drata returned for it.
type uploaded struct {
	name    string
	fileKey string
}

// Publish uploads each file and attaches it to the evidence item at
// evidenceID. A file whose name matches an existing *current* (non-archived)
// artifact on the item replaces that artifact in place via replaceArtifacts
// — preserving the artifact's ID and version history instead of piling up a
// duplicate every run; a file with no matching artifact is added via
// newArtifacts.
func (d *Drata) Publish(workspaceID, evidenceID int, files []File) error {
	client := d.httpClient()

	ups := make([]uploaded, 0, len(files))
	for _, f := range files {
		fileKey, err := d.uploadFile(client, workspaceID, f)
		if err != nil {
			return err
		}
		ups = append(ups, uploaded{name: f.Name, fileKey: fileKey})
	}

	current, err := d.currentArtifacts(client, workspaceID, evidenceID)
	if err != nil {
		return err
	}

	filedAt := time.Now().UTC().Format("2006-01-02")
	var newArtifacts, replaceArtifacts []map[string]any
	for _, u := range ups {
		artifact := map[string]any{
			"artifactType": "S3_FILE",
			"fileKey":      u.fileKey,
			"artifactName": u.name,
			"filedAt":      filedAt,
		}
		if id, ok := current[u.name]; ok {
			artifact["existingArtifactId"] = id
			replaceArtifacts = append(replaceArtifacts, artifact)
		} else {
			newArtifacts = append(newArtifacts, artifact)
		}
	}

	return d.updateEvidence(client, workspaceID, evidenceID, newArtifacts, replaceArtifacts)
}

// uploadFile pre-uploads f via POST /workspaces/{workspaceId}/evidence-files
// and returns the fileKey to reference from the evidence item. Drata
// restricts this endpoint to a documented extension allowlist that includes
// both .csv and .md, so changes.csv and summary.md upload unmodified.
func (d *Drata) uploadFile(client *http.Client, workspaceID int, f File) (string, error) {
	body, contentType, err := encodeMultipart(
		multipartField{Name: "file", Filename: f.Name, ContentType: f.ContentType, Value: f.Data},
	)
	if err != nil {
		return "", fmt.Errorf("drata upload %s: %w", f.Name, err)
	}

	u := fmt.Sprintf("%s/workspaces/%d/evidence-files", d.BaseURL, workspaceID)
	resp, err := httpretry.Do(client, func() (*http.Request, error) {
		req, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+d.APIKey)
		return req, nil
	})
	if err != nil {
		return "", fmt.Errorf("drata upload %s: %w", f.Name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("drata upload %s: %s: %s", f.Name, resp.Status, readErrorBody(resp))
	}

	var out struct {
		FileKey string `json:"fileKey"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("drata upload %s: decoding response: %w", f.Name, err)
	}
	if out.FileKey == "" {
		return "", fmt.Errorf("drata upload %s: response had no fileKey", f.Name)
	}
	return out.FileKey, nil
}

// currentArtifacts fetches the evidence item's artifacts (expand=artifacts)
// and returns the non-archived ones keyed by artifactName, so Publish can
// tell which uploaded files already have a live artifact to replace.
func (d *Drata) currentArtifacts(client *http.Client, workspaceID, evidenceID int) (map[string]int, error) {
	q := url.Values{"expand[]": {"artifacts"}}
	u := fmt.Sprintf("%s/workspaces/%d/evidence/%d?%s", d.BaseURL, workspaceID, evidenceID, q.Encode())

	resp, err := httpretry.Do(client, func() (*http.Request, error) {
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+d.APIKey)
		return req, nil
	})
	if err != nil {
		return nil, fmt.Errorf("drata get evidence %d: %w", evidenceID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("drata get evidence %d: %s: %s", evidenceID, resp.Status, readErrorBody(resp))
	}

	var ev struct {
		Artifacts struct {
			Data []struct {
				ID           int     `json:"id"`
				ArtifactName string  `json:"artifactName"`
				ArchivedAt   *string `json:"archivedAt"`
			} `json:"data"`
		} `json:"artifacts"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ev); err != nil {
		return nil, fmt.Errorf("drata get evidence %d: decoding response: %w", evidenceID, err)
	}

	current := make(map[string]int, len(ev.Artifacts.Data))
	for _, a := range ev.Artifacts.Data {
		if a.ArchivedAt == nil {
			current[a.ArtifactName] = a.ID
		}
	}
	return current, nil
}

// updateEvidence sends PUT /workspaces/{workspaceId}/evidence/{evidenceId}
// with the new and/or replacement artifacts; either slice may be empty, in
// which case its key is omitted so the partial-update semantics of the
// endpoint leave the other side untouched.
func (d *Drata) updateEvidence(client *http.Client, workspaceID, evidenceID int, newArtifacts, replaceArtifacts []map[string]any) error {
	payload := map[string]any{}
	if len(newArtifacts) > 0 {
		payload["newArtifacts"] = newArtifacts
	}
	if len(replaceArtifacts) > 0 {
		payload["replaceArtifacts"] = replaceArtifacts
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("drata update evidence %d: %w", evidenceID, err)
	}

	u := fmt.Sprintf("%s/workspaces/%d/evidence/%d", d.BaseURL, workspaceID, evidenceID)
	resp, err := httpretry.Do(client, func() (*http.Request, error) {
		req, err := http.NewRequest(http.MethodPut, u, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+d.APIKey)
		return req, nil
	})
	if err != nil {
		return fmt.Errorf("drata update evidence %d: %w", evidenceID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("drata update evidence %d: %s: %s", evidenceID, resp.Status, readErrorBody(resp))
	}
	io.Copy(io.Discard, resp.Body)
	return nil
}
