package text

import (
	"strings"
	"testing"

	"github.com/sufield/stave/internal/app/contracts"
)

func TestWriteExplainText(t *testing.T) {
	result := contracts.ExplainResult{
		ControlID:   "CTL.S3.PUBLIC.001",
		Name:        "No Public S3 Bucket Read",
		Description: "Buckets must not allow public read access.",
		Type:        "unsafe_state",
		MatchedFields: []string{
			"properties.storage.access.public_read",
		},
		Rules: []contracts.ExplainRule{
			{Path: "properties.storage.access.public_read", Op: "eq", Value: true, From: "any"},
		},
		MinimalObservation: map[string]any{
			"properties": map[string]any{
				"storage": map[string]any{
					"access": map[string]any{
						"public_read": true,
					},
				},
			},
		},
	}

	var b strings.Builder
	err := WriteExplainText(&b, result)
	if err != nil {
		t.Fatalf("WriteExplainText() error = %v", err)
	}
	out := b.String()

	checks := []string{
		"Control: CTL.S3.PUBLIC.001",
		"Name: No Public S3 Bucket Read",
		"Type: unsafe_state",
		"Matched fields:",
		"properties.storage.access.public_read",
		"Rules:",
		"eq",
		"Minimal observation snippet:",
		"stave validate",
	}
	for _, c := range checks {
		if !strings.Contains(out, c) {
			t.Errorf("output missing %q\n\nFull output:\n%s", c, out)
		}
	}
}
