package engine

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evidence"
)

func TestBuildEvidencePackage_ViolationFinding(t *testing.T) {
	controls := []policy.ControlDefinition{{
		ID:          "CTL.S3.PUBLIC.001",
		Name:        "No public S3",
		Description: "S3 buckets must not be public",
		Severity:    policy.SeverityCritical,
		Compliance:  policy.ComplianceMapping{"hipaa": "164.312(a)(1)", "soc2": "CC6.1"},
	}}

	findings := []evaluation.Finding{{
		ControlID:   "CTL.S3.PUBLIC.001",
		ControlName: "No public S3",
		AssetID:     "arn:aws:s3:::my-bucket",
		Evidence: evaluation.Evidence{
			TemporalRisk: "Public for 48h",
		},
	}}

	snap := &asset.Snapshot{
		CapturedAt: time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
		Assets: []asset.Asset{{
			ID:         "arn:aws:s3:::my-bucket",
			Properties: map[string]any{"storage": map[string]any{"access": map[string]any{"public_read": true}}},
		}},
	}

	pkg := buildEvidencePackage(findings, nil, controls, snap, time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC))

	if pkg == nil {
		t.Fatal("expected non-nil package")
	}
	// 1 finding × 2 citations = 2 records
	if pkg.TotalRecords() != 2 {
		t.Fatalf("TotalRecords = %d, want 2", pkg.TotalRecords())
	}
	if pkg.FailCount != 2 {
		t.Errorf("FailCount = %d, want 2", pkg.FailCount)
	}
	for _, r := range pkg.Records {
		if r.Verdict != evidence.VerdictFail {
			t.Errorf("expected VerdictFail, got %v", r.Verdict)
		}
		if r.ControlID != "CTL.S3.PUBLIC.001" {
			t.Errorf("ControlID = %q", r.ControlID)
		}
	}
}

func TestBuildEvidencePackage_PassCheck(t *testing.T) {
	controls := []policy.ControlDefinition{{
		ID:         "CTL.S3.ENCRYPT.001",
		Name:       "Encrypted",
		Severity:   policy.SeverityHigh,
		Compliance: policy.ComplianceMapping{"soc2": "CC6.7"},
	}}

	checks := []evaluation.ResourceCheck{{
		ControlID: "CTL.S3.ENCRYPT.001",
		AssetID:   "arn:aws:s3:::secure",
		Verdict:   evaluation.VerdictPass,
	}}

	snap := &asset.Snapshot{
		CapturedAt: time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
	}

	pkg := buildEvidencePackage(nil, checks, controls, snap, time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC))

	if pkg.TotalRecords() != 1 {
		t.Fatalf("TotalRecords = %d, want 1", pkg.TotalRecords())
	}
	if pkg.PassCount != 1 {
		t.Errorf("PassCount = %d, want 1", pkg.PassCount)
	}
	if pkg.Records[0].Verdict != evidence.VerdictPass {
		t.Errorf("Verdict = %v", pkg.Records[0].Verdict)
	}
}

func TestBuildEvidencePackage_NoComplianceSkipped(t *testing.T) {
	controls := []policy.ControlDefinition{{
		ID:   "CTL.CUSTOM.001",
		Name: "Custom",
		// No Compliance mapping
	}}

	findings := []evaluation.Finding{{
		ControlID: "CTL.CUSTOM.001",
		AssetID:   "arn:aws:s3:::test",
	}}

	pkg := buildEvidencePackage(findings, nil, controls, nil, time.Now())

	if pkg.TotalRecords() != 0 {
		t.Errorf("TotalRecords = %d, want 0 for control without compliance", pkg.TotalRecords())
	}
}

func TestBuildEvidencePackage_NilSnapshot(t *testing.T) {
	controls := []policy.ControlDefinition{{
		ID:                "CTL.S3.PUBLIC.001",
		Name:              "No public",
		Severity:          policy.SeverityCritical,
		Compliance:        policy.ComplianceMapping{"hipaa": "164.312(a)(1)"},
		ObservationFields: []string{"storage.access.public_read"},
	}}

	findings := []evaluation.Finding{{
		ControlID: "CTL.S3.PUBLIC.001",
		AssetID:   "arn:aws:s3:::bucket",
	}}

	// nil snapshot — observation properties should be empty, not panic
	pkg := buildEvidencePackage(findings, nil, controls, nil, time.Now())

	if pkg.TotalRecords() != 1 {
		t.Fatalf("TotalRecords = %d, want 1", pkg.TotalRecords())
	}
	if len(pkg.Records[0].ReasoningTrace.ObservationProperties) != 0 {
		t.Errorf("expected empty observation properties with nil snapshot")
	}
}

func TestBuildEvidencePackage_ObservationFieldsExtracted(t *testing.T) {
	controls := []policy.ControlDefinition{{
		ID:                "CTL.S3.PUBLIC.001",
		Name:              "No public",
		Severity:          policy.SeverityCritical,
		Compliance:        policy.ComplianceMapping{"hipaa": "164.312(a)(1)"},
		ObservationFields: []string{"storage.access.public_read"},
	}}

	findings := []evaluation.Finding{{
		ControlID: "CTL.S3.PUBLIC.001",
		AssetID:   "arn:aws:s3:::bucket",
	}}

	snap := &asset.Snapshot{
		CapturedAt: time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
		Assets: []asset.Asset{{
			ID: "arn:aws:s3:::bucket",
			Properties: map[string]any{
				"storage": map[string]any{
					"access": map[string]any{
						"public_read": true,
					},
				},
			},
		}},
	}

	pkg := buildEvidencePackage(findings, nil, controls, snap, time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC))

	obs := pkg.Records[0].ReasoningTrace.ObservationProperties
	if len(obs) != 1 {
		t.Fatalf("len(ObservationProperties) = %d, want 1", len(obs))
	}
	if obs[0].Field != "storage.access.public_read" || obs[0].Value != "true" {
		t.Errorf("observation = %+v", obs[0])
	}
}

func TestIsSensitiveField(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		{"db_password", true},
		{"auth_token", true},
		{"api_secret", true},
		{"region", false},
		{"enabled", false},
		{"public_read", false},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			if got := isSensitiveField(tt.key); got != tt.want {
				t.Errorf("isSensitiveField(%q) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}
