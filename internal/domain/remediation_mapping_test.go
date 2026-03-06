package domain

import (
	"testing"

	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
)

func TestRemediationMapper_MapFinding(t *testing.T) {
	mapper := remediation.NewMapper()

	tests := []struct {
		name           string
		controlID      string
		wantAction     string
		wantDescSubstr string
	}{
		{
			name:           "public exposure control",
			controlID:      "CTL.S3.PUBLIC.001",
			wantAction:     "Remove public access, confirm via new snapshot.",
			wantDescSubstr: "publicly exposed",
		},
		{
			name:           "state exposure control",
			controlID:      "CTL.S3.ENCRYPT.001",
			wantAction:     "Review and correct the state configuration, verify in new snapshot.",
			wantDescSubstr: "unsafe state",
		},
		{
			name:           "unknown control pattern",
			controlID:      "CTL.UNKNOWN.001",
			wantAction:     "Review the unsafe configuration and remediate.",
			wantDescSubstr: "violation detected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := evaluation.Finding{
				ControlID: kernel.ControlID(tt.controlID),
				AssetID:   "test-resource",
			}

			remediation := mapper.MapFinding(finding)

			if remediation.Action != tt.wantAction {
				t.Errorf("Action = %q, want %q", remediation.Action, tt.wantAction)
			}
			if !contains(remediation.Description, tt.wantDescSubstr) {
				t.Errorf("Description = %q, want substring %q", remediation.Description, tt.wantDescSubstr)
			}
		})
	}
}

func TestRemediationMapper_YAMLRemediationPrecedence(t *testing.T) {
	mapper := remediation.NewMapper()

	yamlRemediation := &policy.RemediationSpec{
		Description: "Bucket has public read access via policy.",
		Action:      "Enable S3 Public Access Block (all four settings).",
	}

	finding := evaluation.Finding{
		ControlID:          "CTL.S3.PUBLIC.001",
		AssetID:            "arn:aws:s3:::my-bucket",
		ControlRemediation: yamlRemediation,
	}

	remediation := mapper.MapFinding(finding)

	if remediation.Description != yamlRemediation.Description {
		t.Errorf("Description = %q, want %q", remediation.Description, yamlRemediation.Description)
	}
	if remediation.Action != yamlRemediation.Action {
		t.Errorf("Action = %q, want %q", remediation.Action, yamlRemediation.Action)
	}
}

func TestRemediationMapper_YAMLExampleFieldFlowsThrough(t *testing.T) {
	mapper := remediation.NewMapper()

	yamlRemediation := &policy.RemediationSpec{
		Description: "Bucket has public read access via policy.",
		Action:      "Enable S3 Public Access Block (all four settings).",
		Example:     "{\n  \"storage\": {\n    \"visibility\": {\n      \"public_read\": false\n    }\n  }\n}\n",
	}

	finding := evaluation.Finding{
		ControlID:          "CTL.S3.PUBLIC.001",
		AssetID:            "arn:aws:s3:::my-bucket",
		ControlRemediation: yamlRemediation,
	}

	remediation := mapper.MapFinding(finding)

	if remediation.Example != yamlRemediation.Example {
		t.Errorf("Example = %q, want %q", remediation.Example, yamlRemediation.Example)
	}
}

func TestRemediationMapper_FallbackWhenNoYAMLRemediation(t *testing.T) {
	mapper := remediation.NewMapper()

	// Finding without ControlRemediation should fall back to prefix mapping
	finding := evaluation.Finding{
		ControlID: "CTL.S3.PUBLIC.001",
		AssetID:   "test-resource",
	}

	remediation := mapper.MapFinding(finding)

	if remediation.Action != "Remove public access, confirm via new snapshot." {
		t.Errorf("Action = %q, want prefix-based fallback", remediation.Action)
	}
}

func TestRemediationMapper_EnrichFindings(t *testing.T) {
	mapper := remediation.NewMapper()

	result := evaluation.Result{
		Findings: []evaluation.Finding{
			{ControlID: "CTL.S3.PUBLIC.001", AssetID: "bucket-1"},
			{ControlID: "CTL.S3.ENCRYPT.001", AssetID: "bucket-2"},
		},
	}

	enriched := mapper.EnrichFindings(result)

	if len(enriched) != 2 {
		t.Fatalf("expected 2 enriched findings, got %d", len(enriched))
	}

	// First finding should have public exposure remediation
	if enriched[0].RemediationSpec.Action != "Remove public access, confirm via new snapshot." {
		t.Errorf("first remediation action = %q", enriched[0].RemediationSpec.Action)
	}

	// Second finding should have state remediation
	if enriched[1].RemediationSpec.Action != "Review and correct the state configuration, verify in new snapshot." {
		t.Errorf("second remediation action = %q", enriched[1].RemediationSpec.Action)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && stringContains(s, substr)))
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
