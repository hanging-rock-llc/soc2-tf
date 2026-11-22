package awsv4

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Identity is the caller identity of the credentials that ran Terraform.
type Identity struct {
	Account         string `json:"account"`
	ARN             string `json:"arn"`
	RoleName        string `json:"role_name,omitempty"`
	RoleSessionName string `json:"role_session_name,omitempty"`
}

// ParseAssumedRoleARN splits arn:aws:sts::123:assumed-role/Role/Session.
func ParseAssumedRoleARN(arn string) (role, session string) {
	i := strings.Index(arn, ":assumed-role/")
	if i < 0 {
		return "", ""
	}
	parts := strings.SplitN(arn[i+len(":assumed-role/"):], "/", 2)
	if len(parts) != 2 {
		return parts[0], ""
	}
	return parts[0], parts[1]
}

// CallerIdentity calls sts:GetCallerIdentity (which needs no IAM permission).
// The role session name it returns is what ties CloudTrail events to a
// specific CI run when the session name includes the run ID.
func CallerIdentity(creds Credentials, region string, hc *http.Client) (*Identity, error) {
	if region == "" {
		region = "us-east-1"
	}
	endpoint := os.Getenv("TFPROOF_STS_ENDPOINT")
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://sts.%s.amazonaws.com/", region)
	}
	body := "Action=GetCallerIdentity&Version=2011-06-15"
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	Sign(req, creds, region, "sts", HashHex([]byte(body)), time.Now())
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("sts GetCallerIdentity: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var out struct {
		Result struct {
			Account string `xml:"Account"`
			Arn     string `xml:"Arn"`
		} `xml:"GetCallerIdentityResult"`
	}
	if err := xml.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("sts GetCallerIdentity: parse: %w", err)
	}
	id := &Identity{Account: out.Result.Account, ARN: out.Result.Arn}
	id.RoleName, id.RoleSessionName = ParseAssumedRoleARN(id.ARN)
	return id, nil
}
