// Package plan parses `terraform show -json` / `tofu show -json` plan output
// and reduces it to the facts an auditor cares about: what was going to
// change, and a stable digest of that change set.
package plan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// Change is a single resource or output change.
type Change struct {
	Address string   `json:"address"`
	Kind    string   `json:"kind"` // resource | output
	Action  string   `json:"action"`
	Actions []string `json:"actions"`
}

// Summary counts changes by normalized action.
type Summary struct {
	Create  int `json:"create"`
	Update  int `json:"update"`
	Delete  int `json:"delete"`
	Replace int `json:"replace"`
	Read    int `json:"read"`
	Forget  int `json:"forget"`
	Import  int `json:"import"`
	NoOp    int `json:"no_op"`
}

// Facts is the audit-relevant reduction of a plan.
type Facts struct {
	FormatVersion    string   `json:"format_version,omitempty"`
	TerraformVersion string   `json:"terraform_version,omitempty"`
	Summary          Summary  `json:"summary"`
	HasChanges       bool     `json:"has_changes"`
	Changes          []Change `json:"changes"`
	// ChangesetDigest is a SHA-256 over the sorted list of non-no-op changes
	// (address + normalized action). Two plans that would make the same
	// changes have the same digest even if they were produced by different
	// runs. It says nothing about attribute values; see ValuesDigest.
	ChangesetDigest string `json:"changeset_digest"`
	// ValuesDigest additionally covers each change's planned end state
	// (`after`, `after_unknown`, `importing`). It is what lets an
	// apply-on-merge re-plan be matched to the plan reviewed on the pull
	// request: same resources, same actions, same resulting values. Prior
	// state (`before`) is excluded so drift alone doesn't cause a mismatch.
	ValuesDigest string `json:"values_digest"`
	JSONSHA256   string `json:"json_sha256"`
}

type rawChange struct {
	Actions      []string        `json:"actions"`
	After        json.RawMessage `json:"after"`
	AfterUnknown json.RawMessage `json:"after_unknown"`
	Importing    json.RawMessage `json:"importing"`
}

type rawPlan struct {
	FormatVersion    string `json:"format_version"`
	TerraformVersion string `json:"terraform_version"`
	ResourceChanges  []struct {
		Address string    `json:"address"`
		Change  rawChange `json:"change"`
	} `json:"resource_changes"`
	OutputChanges map[string]rawChange `json:"output_changes"`
}

// Normalize collapses Terraform's action lists to one verb.
func Normalize(actions []string) string {
	switch strings.Join(actions, ",") {
	case "no-op", "":
		return "no-op"
	case "create":
		return "create"
	case "read":
		return "read"
	case "update":
		return "update"
	case "delete":
		return "delete"
	case "delete,create", "create,delete":
		return "replace"
	case "forget":
		return "forget"
	default:
		return strings.Join(actions, "+")
	}
}

// Parse reduces plan JSON to Facts.
func Parse(data []byte) (*Facts, error) {
	var rp rawPlan
	if err := json.Unmarshal(data, &rp); err != nil {
		return nil, fmt.Errorf("parse plan json: %w", err)
	}
	if rp.FormatVersion == "" {
		return nil, fmt.Errorf("parse plan json: missing format_version (is this `terraform show -json <planfile>` output?)")
	}
	sum := sha256.Sum256(data)
	f := &Facts{
		FormatVersion:    rp.FormatVersion,
		TerraformVersion: rp.TerraformVersion,
		JSONSHA256:       hex.EncodeToString(sum[:]),
		Changes:          []Change{},
	}
	var valueLines []string
	addValues := func(c Change, rc rawChange) error {
		if c.Action == "read" {
			return nil
		}
		// One JSON array per change keeps the fields unambiguous even when an
		// address contains separators.
		tuple, err := json.Marshal([]any{c.Kind, c.Address, c.Action, orNull(rc.After), orNull(rc.AfterUnknown), orNull(rc.Importing)})
		if err != nil {
			return fmt.Errorf("parse plan json: %s: %w", c.Address, err)
		}
		line, err := canonical(tuple)
		if err != nil {
			return fmt.Errorf("parse plan json: %s: %w", c.Address, err)
		}
		valueLines = append(valueLines, line)
		return nil
	}
	for _, rc := range rp.ResourceChanges {
		a := Normalize(rc.Change.Actions)
		importing := len(rc.Change.Importing) > 0 && string(rc.Change.Importing) != "null"
		switch a {
		case "no-op":
			if importing {
				f.Summary.Import++
				a = "import"
			} else {
				f.Summary.NoOp++
				continue
			}
		case "create":
			f.Summary.Create++
		case "update":
			f.Summary.Update++
		case "delete":
			f.Summary.Delete++
		case "replace":
			f.Summary.Replace++
		case "read":
			f.Summary.Read++
		case "forget":
			f.Summary.Forget++
		}
		c := Change{Address: rc.Address, Kind: "resource", Action: a, Actions: rc.Change.Actions}
		if err := addValues(c, rc.Change); err != nil {
			return nil, err
		}
		f.Changes = append(f.Changes, c)
	}
	for name, oc := range rp.OutputChanges {
		a := Normalize(oc.Actions)
		if a == "no-op" {
			continue
		}
		c := Change{Address: "output." + name, Kind: "output", Action: a, Actions: oc.Actions}
		if err := addValues(c, oc); err != nil {
			return nil, err
		}
		f.Changes = append(f.Changes, c)
	}
	sort.Slice(f.Changes, func(i, j int) bool { return f.Changes[i].Address < f.Changes[j].Address })
	f.HasChanges = false
	for _, c := range f.Changes {
		if c.Action != "read" {
			f.HasChanges = true
			break
		}
	}
	f.ChangesetDigest = Digest(f.Changes)
	sort.Strings(valueLines)
	vh := sha256.Sum256([]byte(strings.Join(valueLines, "\n")))
	f.ValuesDigest = hex.EncodeToString(vh[:])
	return f, nil
}

func orNull(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("null")
	}
	return raw
}

// canonical re-encodes a JSON value with sorted object keys and numbers kept
// verbatim, so equal values always produce equal bytes.
func canonical(raw []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}

// Digest computes the changeset digest over changes that mutate something.
// Data-source reads are excluded because they don't change infrastructure
// and frequently differ between otherwise identical plans.
func Digest(changes []Change) string {
	lines := make([]string, 0, len(changes))
	for _, c := range changes {
		if c.Action == "read" {
			continue
		}
		lines = append(lines, c.Kind+"|"+c.Address+"|"+c.Action)
	}
	sort.Strings(lines)
	h := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(h[:])
}

// FileSHA256 hashes a file on disk.
func FileSHA256(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

// ShowJSON runs `<binary> show -json <planfile>` in dir and returns stdout.
func ShowJSON(binary, dir, planFile string) ([]byte, error) {
	cmd := exec.Command(binary, "show", "-json", planFile)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TF_IN_AUTOMATION=1")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s show -json %s: %w: %s", binary, planFile, err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}
