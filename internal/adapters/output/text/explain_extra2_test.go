package text

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/predicate"
)

func TestWriteExplainText_Full(t *testing.T) {
	result := contracts.ExplainResult{
		ControlID:   "CTL.PUB.READ.001",
		Name:        "Public Read Access",
		Description: "Detects public read on S3",
		Type:        "unsafe_duration",
		MatchedFields: []string{
			"properties.public_access.block_public_acls",
			"properties.public_access.block_public_policy",
		},
		Rules: []contracts.ExplainRule{
			{
				Path:  "properties.public_access.block_public_acls",
				Op:    predicate.OpEq,
				Value: false,
				From:  "unsafe_predicate.any[0]",
			},
		},
		MinimalObservation: map[string]any{
			"public_access": map[string]any{
				"block_public_acls": false,
			},
		},
	}

	var buf bytes.Buffer
	err := WriteExplainText(&buf, result)
	if err != nil {
		t.Fatalf("WriteExplainText: %v", err)
	}

	out := buf.String()
	expects := []string{
		"CTL.PUB.READ.001",
		"Public Read Access",
		"Matched fields:",
		"block_public_acls",
		"Rules:",
		"unsafe_predicate",
		"Minimal observation",
		"observations",
	}
	for _, exp := range expects {
		if !strings.Contains(out, exp) {
			t.Errorf("output missing %q", exp)
		}
	}
}

func TestWriteExplainText_EmptyFields(t *testing.T) {
	result := contracts.ExplainResult{
		ControlID:          "CTL.X.001",
		Name:               "Empty",
		Description:        "Test",
		Type:               "unsafe_state",
		MatchedFields:      nil,
		Rules:              nil,
		MinimalObservation: nil,
	}

	var buf bytes.Buffer
	err := WriteExplainText(&buf, result)
	if err != nil {
		t.Fatalf("WriteExplainText: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "CTL.X.001") {
		t.Error("missing control ID")
	}
}
