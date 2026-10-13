package telemetry

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
)

func makeAssessment(findings []remediation.Finding) *report.Assessment {
	return &report.Assessment{
		Run: evaluation.RunInfo{
			EvalTime:          time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC),
			PolicyFingerprint: kernel.Digest("sha256:abcd1234"),
			EvaluatedState:    "deployed",
		},
		Status:   evaluation.StateNonCompliant,
		Findings: findings,
	}
}

func TestMapper_ViolationFinding(t *testing.T) {
	a := makeAssessment([]remediation.Finding{
		{
			ControlID:       "CTL.S3.PUBLIC.001",
			ControlName:     "Public Bucket Access",
			ControlSeverity: policy.SeverityCritical,
			AssetID:         asset.ID("arn:aws:s3:::prod-phi"),
			AssetType:       "aws_s3_bucket",
		},
	})

	events := MapAssessment(a, Filter{}, nil)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	e := events[0]
	if e.SchemaVersion != "telemetry.v2" {
		t.Errorf("schema_version = %q", e.SchemaVersion)
	}
	if e.ControlID != "CTL.S3.PUBLIC.001" {
		t.Errorf("control_id = %q", e.ControlID)
	}
	if e.Verdict != evaluation.VerdictViolation {
		t.Errorf("verdict = %q", e.Verdict)
	}
	if e.PolicyFingerprint != "sha256:abcd1234" {
		t.Errorf("policy_fingerprint = %q", e.PolicyFingerprint)
	}
	if e.Status != "NON_COMPLIANT" {
		t.Errorf("status = %q", e.Status)
	}
}

func TestMapper_EmptyFindings(t *testing.T) {
	a := makeAssessment(nil)
	events := MapAssessment(a, Filter{}, nil)
	if len(events) != 0 {
		t.Fatalf("expected 0 events, got %d", len(events))
	}
}

func TestMapper_SeverityFilter(t *testing.T) {
	a := makeAssessment([]remediation.Finding{
		{ControlID: "CTL.A", ControlSeverity: policy.SeverityCritical, AssetID: "a"},
		{ControlID: "CTL.B", ControlSeverity: policy.SeverityHigh, AssetID: "b"},
		{ControlID: "CTL.C", ControlSeverity: policy.SeverityMedium, AssetID: "c"},
	})

	filter := Filter{Severities: map[string]struct{}{"critical": {}}}
	events := MapAssessment(a, filter, nil)
	if len(events) != 1 {
		t.Fatalf("expected 1 critical event, got %d", len(events))
	}
	if events[0].ControlID != "CTL.A" {
		t.Errorf("expected CTL.A, got %s", events[0].ControlID)
	}
}

func TestMapper_ResourceFilter(t *testing.T) {
	a := makeAssessment([]remediation.Finding{
		{Finding: evaluation.Finding{ControlID: "CTL.A", AssetID: "arn:aws:s3:::bucket-a"}},
		{Finding: evaluation.Finding{ControlID: "CTL.B", AssetID: "arn:aws:s3:::bucket-b"}},
	})

	filter := Filter{ResourceARN: "arn:aws:s3:::bucket-a"}
	events := MapAssessment(a, filter, nil)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].ResourceID != "arn:aws:s3:::bucket-a" {
		t.Errorf("expected bucket-a, got %s", events[0].ResourceID)
	}
}

func TestMapper_ControlFingerprint(t *testing.T) {
	a := makeAssessment([]remediation.Finding{
		{Finding: evaluation.Finding{ControlID: "CTL.A", AssetID: "a"}},
	})
	fps := ControlFingerprints{"CTL.A": "sha256:per-control-hash"}
	events := MapAssessment(a, Filter{}, fps)
	if len(events) != 1 {
		t.Fatal("expected 1 event")
	}
	if events[0].ControlFingerprint != "sha256:per-control-hash" {
		t.Errorf("control_fingerprint = %q", events[0].ControlFingerprint)
	}
}

func TestMapper_EnvironmentalScore(t *testing.T) {
	a := makeAssessment([]remediation.Finding{
		{Finding: evaluation.Finding{ControlID: "CTL.A", AssetID: "a"}},
	})
	events := MapAssessment(a, Filter{}, nil)
	if len(events) != 1 {
		t.Fatal("expected 1 event")
	}
	// Default: base_impact=5, sensitivity=1.0, exposure=1.0 → 5.0
	if events[0].EnvironmentalScore == nil || *events[0].EnvironmentalScore != 5.0 {
		t.Errorf("environmental_score = %v, want 5.0", events[0].EnvironmentalScore)
	}
}

func TestMapper_WithWindows(t *testing.T) {
	a := makeAssessment([]remediation.Finding{
		{Finding: evaluation.Finding{ControlID: "CTL.A", AssetID: "bucket-a"}},
	})
	tracker := NewWindowTracker()
	events := MapAssessmentWithWindows(a, Filter{}, nil, tracker)
	if len(events) != 1 {
		t.Fatal("expected 1 event")
	}
	if events[0].WindowID == nil {
		t.Fatal("window_id should be set in window mode")
	}
	if *events[0].WindowID != "bucket-a/CTL.A/2026-01-11T00:00:00Z" {
		t.Errorf("window_id = %q", *events[0].WindowID)
	}
}

func TestChainIDs_DomainMethods(t *testing.T) {
	c := ChainIDs{"CHAIN.001", "CHAIN.002"}
	if c.Len() != 2 {
		t.Errorf("Len() = %d, want 2", c.Len())
	}
	if !c.Contains("CHAIN.001") {
		t.Error("Contains(CHAIN.001) = false, want true")
	}
	if c.Contains("CHAIN.003") {
		t.Error("Contains(CHAIN.003) = true, want false")
	}
}

func TestExposureScore_DomainMethods(t *testing.T) {
	zero := ExposureScore(0)
	if !zero.IsZero() {
		t.Error("IsZero() = false for 0, want true")
	}
	if zero.Float64() != 0 {
		t.Errorf("Float64() = %v, want 0", zero.Float64())
	}

	high := ExposureScore(8.5)
	if high.IsZero() {
		t.Error("IsZero() = true for 8.5, want false")
	}
	if !high.IsHigh(7.0) {
		t.Error("IsHigh(7.0) = false for 8.5, want true")
	}
	if high.IsHigh(9.0) {
		t.Error("IsHigh(9.0) = true for 8.5, want false")
	}
}

func TestEvents_DomainMethods(t *testing.T) {
	ev := Events{
		{ControlID: "CTL.A", Severity: policy.SeverityCritical, ResourceID: "res-1", Verdict: evaluation.VerdictViolation},
		{ControlID: "CTL.B", Severity: policy.SeverityHigh, ResourceID: "res-2", Verdict: evaluation.VerdictPass},
	}

	if ev.Len() != 2 {
		t.Errorf("Len() = %d, want 2", ev.Len())
	}
	if ev.ByControl("CTL.A").Len() != 1 {
		t.Errorf("ByControl(CTL.A) = %d, want 1", ev.ByControl("CTL.A").Len())
	}
	if ev.BySeverity(policy.SeverityCritical).Len() != 1 {
		t.Errorf("BySeverity(Critical) = %d, want 1", ev.BySeverity(policy.SeverityCritical).Len())
	}
	if ev.ByResource("res-1").Len() != 1 {
		t.Errorf("ByResource(res-1) = %d, want 1", ev.ByResource("res-1").Len())
	}
	if ev.Violations().Len() != 1 {
		t.Errorf("Violations() = %d, want 1", ev.Violations().Len())
	}

	var empty Events
	if empty.Len() != 0 || empty.ByControl("CTL.A") != nil || empty.BySeverity(policy.SeverityLow) != nil || empty.ByResource("res") != nil || empty.Violations() != nil {
		t.Error("empty Events methods failed")
	}
}
