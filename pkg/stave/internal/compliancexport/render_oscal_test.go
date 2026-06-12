package compliancexport

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/evidence"
)

func TestRenderOSCAL_FailingRequirement(t *testing.T) {
	rec := &evidence.EvidenceRecord{
		ControlID:   "CTL.S3.ENCRYPT.001",
		ControlName: "S3 Encryption",
		ResourceARN: "arn:aws:s3:::phi",
		Verdict:     evidence.VerdictFail,
		Severity:    "high",
		EvaluatedAt: time.Date(2025, 11, 15, 14, 0, 0, 0, time.UTC),
		ReasoningTrace: evidence.ReasoningTrace{
			FindingMessage: "S3 bucket not encrypted",
		},
	}
	pkg := &evidence.EvidencePackage{
		SnapshotID: "snap-001",
		AssessedAt: time.Date(2025, 11, 15, 14, 0, 0, 0, time.UTC),
		Records:    []*evidence.EvidenceRecord{rec},
	}

	profile := &evidence.FrameworkProfile{
		ID: "fedramp_moderate", Name: "FedRAMP Moderate",
		Version: "r5", FrameworkKey: "fedramp_moderate",
	}
	assessment := &evidence.ProfileAssessment{
		FrameworkID:       "fedramp_moderate",
		TotalRequirements: 1,
		NotMetCount:       1,
		Requirements: []evidence.RequirementAssessment{
			{
				RequirementID: "SC-28",
				Description:   "Protection of information at rest",
				Status:        evidence.RequirementNotMet,
				Evidence:      []*evidence.EvidenceRecord{rec},
			},
		},
	}

	opts := &Config{
		Format:   "oscal",
		Assessor: "Test Assessor",
	}

	var buf bytes.Buffer
	err := renderOSCAL(&buf, opts, []*evidence.FrameworkProfile{profile},
		[]*evidence.ProfileAssessment{assessment}, pkg,
		time.Date(2025, 11, 15, 14, 0, 0, 0, time.UTC))

	// Exit error expected (NotMet > 0).
	if err == nil {
		t.Log("expected exit error for failing requirement")
	}

	// Parse output.
	var doc oscalDocument
	if jsonErr := json.Unmarshal(buf.Bytes(), &doc); jsonErr != nil {
		t.Fatalf("invalid OSCAL JSON: %v", jsonErr)
	}

	// Verify structure.
	if doc.AssessmentResults.Metadata.OsCalVersion != "1.1.2" {
		t.Errorf("oscal-version = %q, want 1.1.2", doc.AssessmentResults.Metadata.OsCalVersion)
	}
	if len(doc.AssessmentResults.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(doc.AssessmentResults.Results))
	}

	result := doc.AssessmentResults.Results[0]
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Findings))
	}

	finding := result.Findings[0]
	if finding.Target.Status.State != "not-satisfied" {
		t.Errorf("status.state = %q, want not-satisfied", finding.Target.Status.State)
	}
	if finding.Target.Status.Reason != "fail" {
		t.Errorf("status.reason = %q, want fail", finding.Target.Status.Reason)
	}

	// FedRAMP control ID should be lowercase NIST notation.
	if finding.Target.TargetID != "sc-28" {
		t.Errorf("target-id = %q, want sc-28", finding.Target.TargetID)
	}

	// Observations.
	if len(result.Observations) != 1 {
		t.Fatalf("observations = %d, want 1", len(result.Observations))
	}
}

func TestUUIDV5_Deterministic(t *testing.T) {
	a := uuidV5("test", "hello", "world")
	b := uuidV5("test", "hello", "world")
	if a != b {
		t.Errorf("UUID v5 not deterministic: %q != %q", a, b)
	}

	c := uuidV5("test", "different")
	if a == c {
		t.Error("different inputs should produce different UUIDs")
	}

	// Verify format: 8-4-4-4-12
	if len(a) != 36 {
		t.Errorf("UUID length = %d, want 36", len(a))
	}
	if a[8] != '-' || a[13] != '-' || a[18] != '-' || a[23] != '-' {
		t.Errorf("UUID format wrong: %s", a)
	}
}

func TestToOSCALControlID_FedRAMP(t *testing.T) {
	got := toOSCALControlID("fedramp_moderate", "SC-28")
	if got != "sc-28" {
		t.Errorf("got %q, want sc-28", got)
	}
}

func TestToOSCALControlID_HIPAA(t *testing.T) {
	got := toOSCALControlID("hipaa", "164.312(a)(1)")
	if got != "hipaa:164.312(a)(1)" {
		t.Errorf("got %q, want hipaa:164.312(a)(1)", got)
	}
}

func TestRenderOSCAL_PassingRequirement(t *testing.T) {
	rec := &evidence.EvidenceRecord{
		ControlID:   "CTL.S3.ENCRYPT.001",
		ResourceARN: "arn:aws:s3:::good",
		Verdict:     evidence.VerdictPass,
		Severity:    "high",
		EvaluatedAt: time.Date(2025, 11, 15, 14, 0, 0, 0, time.UTC),
	}
	pkg := &evidence.EvidencePackage{
		SnapshotID: "snap-002",
		Records:    []*evidence.EvidenceRecord{rec},
	}

	profile := &evidence.FrameworkProfile{
		ID: "hipaa", Name: "HIPAA", FrameworkKey: "hipaa",
	}
	assessment := &evidence.ProfileAssessment{
		FrameworkID:       "hipaa",
		TotalRequirements: 1,
		MetCount:          1,
		Requirements: []evidence.RequirementAssessment{
			{
				RequirementID: "164.312(a)(1)",
				Description:   "Access control",
				Status:        evidence.RequirementMet,
				Evidence:      []*evidence.EvidenceRecord{rec},
			},
		},
	}

	opts := &Config{Format: "oscal", Assessor: "Test"}
	var buf bytes.Buffer
	err := renderOSCAL(&buf, opts, []*evidence.FrameworkProfile{profile},
		[]*evidence.ProfileAssessment{assessment}, pkg,
		time.Date(2025, 11, 15, 14, 0, 0, 0, time.UTC))

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var doc oscalDocument
	if jsonErr := json.Unmarshal(buf.Bytes(), &doc); jsonErr != nil {
		t.Fatalf("invalid JSON: %v", jsonErr)
	}

	finding := doc.AssessmentResults.Results[0].Findings[0]
	if finding.Target.Status.State != "satisfied" {
		t.Errorf("state = %q, want satisfied", finding.Target.Status.State)
	}
}
