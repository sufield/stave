package template

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
)

// VerifyResult holds the outcome of semantic fixture verification.
type VerifyResult struct {
	ExpectedCount int
	ActualCount   int
	MatchedCount  int
	Missing       []Finding // expected but not found
	Unexpected    []Finding // found but not expected
}

// Pass reports whether verification succeeded.
func (r VerifyResult) Pass() bool {
	return len(r.Missing) == 0 && len(r.Unexpected) == 0
}

// Finding is the minimal structure needed for semantic matching.
type Finding struct {
	ControlID  string `json:"control_id"`
	ResourceID string `json:"resource_id"`
}

// Key returns the match key for semantic comparison.
func (f Finding) Key(matchKeys []string) string {
	var parts []string
	for _, k := range matchKeys {
		switch k {
		case "control_id":
			parts = append(parts, f.ControlID)
		case "resource_id":
			parts = append(parts, f.ResourceID)
		}
	}
	return strings.Join(parts, "\x00")
}

// Verify runs semantic matching between expected and actual findings.
func Verify(expected, actual []Finding, matchKeys []string) VerifyResult {
	if len(matchKeys) == 0 {
		matchKeys = []string{"control_id", "resource_id"}
	}

	expectedKeys := make(map[string]Finding, len(expected))
	for _, f := range expected {
		expectedKeys[f.Key(matchKeys)] = f
	}

	actualKeys := make(map[string]Finding, len(actual))
	for _, f := range actual {
		actualKeys[f.Key(matchKeys)] = f
	}

	var matched int
	var missing []Finding
	for key, f := range expectedKeys {
		if _, ok := actualKeys[key]; ok {
			matched++
		} else {
			missing = append(missing, f)
		}
	}

	var unexpected []Finding
	for key, f := range actualKeys {
		if _, ok := expectedKeys[key]; !ok {
			unexpected = append(unexpected, f)
		}
	}

	return VerifyResult{
		ExpectedCount: len(expected),
		ActualCount:   len(actual),
		MatchedCount:  matched,
		Missing:       missing,
		Unexpected:    unexpected,
	}
}

// LoadExpectedFindings reads a JSONL file of expected findings from an fs.FS.
func LoadExpectedFindings(fsys fs.FS, path string) ([]Finding, error) {
	data, err := fs.ReadFile(fsys, path)
	if err != nil {
		return nil, fmt.Errorf("read expected findings %q: %w", path, err)
	}

	var findings []Finding
	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var f Finding
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			return nil, fmt.Errorf("parse finding line: %w", err)
		}
		findings = append(findings, f)
	}
	return findings, nil
}
