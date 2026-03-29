package remediation

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

type stubIDGen struct{}

func (stubIDGen) GenerateID(prefix string, components ...string) string {
	return prefix + "stub"
}

type stubDigester struct{}

func (stubDigester) Digest(components []string, sep byte) kernel.Digest {
	return "stubhash0123456789abcdef"
}

type stubSanitizer struct{}

func (stubSanitizer) ID(id string) string   { return "[REDACTED-ID]" }
func (stubSanitizer) Path(p string) string  { return "[REDACTED-PATH]" }
func (stubSanitizer) Value(v string) string { return "[REDACTED-VAL]" }

// ---------------------------------------------------------------------------
// Mapper.MapFinding
// ---------------------------------------------------------------------------

func TestMapperMapFinding_YAMLDefinedRemediation(t *testing.T) {
	m := NewMapper(stubIDGen{})
	spec := &policy.RemediationSpec{
		Description: "custom desc",
		Action:      "custom action",
	}
	f := evaluation.Finding{
		ControlRemediation: spec,
	}
	got := m.MapFinding(f)
	if got.Description != "custom desc" {
		t.Fatalf("Description = %q", got.Description)
	}
	if got.Action != "custom action" {
		t.Fatalf("Action = %q", got.Action)
	}
}

func TestMapperMapFinding_PublicExposureFallback(t *testing.T) {
	m := NewMapper(stubIDGen{})
	f := evaluation.Finding{
		ControlID: "CTL.S3.PUBLIC.001",
	}
	got := m.MapFinding(f)
	if got.Description != "Resource is exposed to the public internet." {
		t.Fatalf("Description = %q", got.Description)
	}
}

func TestMapperMapFinding_EncryptionFallback(t *testing.T) {
	m := NewMapper(stubIDGen{})
	f := evaluation.Finding{
		ControlID: "CTL.S3.ENCRYPT.001",
	}
	got := m.MapFinding(f)
	if got.Description != "Resource data is not encrypted at rest." {
		t.Fatalf("Description = %q", got.Description)
	}
}

func TestMapperMapFinding_BaselineFallback(t *testing.T) {
	m := NewMapper(stubIDGen{})
	// CTL.CUSTOM.001 matches ClassBaselineViolation (CTL.* prefix)
	f := evaluation.Finding{
		ControlID: "CTL.CUSTOM.001",
	}
	got := m.MapFinding(f)
	if got.Description != "Resource configuration deviates from security baseline." {
		t.Fatalf("Description = %q", got.Description)
	}
}

func TestMapperMapFinding_DefaultFallback(t *testing.T) {
	m := NewMapper(stubIDGen{})
	// Non-CTL prefix triggers the default case
	f := evaluation.Finding{
		ControlID: "NONSTANDARD.001",
	}
	got := m.MapFinding(f)
	if got.Description != "Security control violation detected." {
		t.Fatalf("Description = %q", got.Description)
	}
}

// ---------------------------------------------------------------------------
// Mapper.MapFindings
// ---------------------------------------------------------------------------

func TestMapperMapFindings(t *testing.T) {
	m := NewMapper(stubIDGen{})
	result := evaluation.Result{
		Findings: []evaluation.Finding{
			{ControlID: "CTL.S3.PUBLIC.001"},
			{ControlID: "CTL.S3.ENCRYPT.001"},
		},
	}
	specs := m.MapFindings(result)
	if len(specs) != 2 {
		t.Fatalf("len = %d", len(specs))
	}
}

// ---------------------------------------------------------------------------
// Mapper.EnrichFindings
// ---------------------------------------------------------------------------

func TestMapperEnrichFindings(t *testing.T) {
	m := NewMapper(stubIDGen{})
	result := evaluation.Result{
		Findings: []evaluation.Finding{
			{ControlID: "CTL.S3.PUBLIC.001", AssetID: "bucket-1", AssetType: "aws_s3_bucket"},
		},
	}
	enriched := m.EnrichFindings(result)
	if len(enriched) != 1 {
		t.Fatalf("len = %d", len(enriched))
	}
	if enriched[0].RemediationSpec.Description == "" {
		t.Fatal("RemediationSpec should be populated")
	}
	// Public exposure should have a remediation plan
	if enriched[0].RemediationPlan == nil {
		t.Fatal("RemediationPlan should be populated for public exposure")
	}
}

// ---------------------------------------------------------------------------
// Finding.Sanitized
// ---------------------------------------------------------------------------

func TestFindingSanitized(t *testing.T) {
	f := Finding{
		Finding: evaluation.Finding{
			ControlID: "CTL.S3.PUBLIC.001",
			AssetID:   "bucket-secret",
			Source:    &asset.SourceRef{File: "/real/path.json", Line: 1},
			Evidence: evaluation.Evidence{
				Misconfigurations: []policy.Misconfiguration{
					{ActualValue: "secret-data"},
				},
				SourceEvidence: &evaluation.SourceEvidence{
					IdentityStatements: []kernel.StatementID{"stmt-1"},
					ResourceGrantees:   []kernel.GranteeID{"grantee-1"},
				},
			},
		},
		RemediationPlan: &evaluation.RemediationPlan{
			Target: evaluation.RemediationTarget{
				AssetID: "bucket-secret",
			},
		},
	}

	sanitized := f.Sanitized(stubSanitizer{})
	if sanitized.AssetID == "bucket-secret" {
		t.Fatal("AssetID should be sanitized")
	}
	if sanitized.Source.File == "/real/path.json" {
		t.Fatal("Source.File should be sanitized")
	}
	if sanitized.Evidence.Misconfigurations[0].ActualValue != kernel.Redacted {
		t.Fatal("Misconfiguration ActualValue should be sanitized")
	}
	if sanitized.Evidence.SourceEvidence.IdentityStatements[0] == "stmt-1" {
		t.Fatal("IdentityStatements should be sanitized")
	}
	if sanitized.RemediationPlan.Target.AssetID == "bucket-secret" {
		t.Fatal("RemediationPlan target should be sanitized")
	}

	// Original should be unmodified
	if f.AssetID != "bucket-secret" {
		t.Fatal("original was mutated")
	}
}

func TestFindingSanitized_NilFields(t *testing.T) {
	f := Finding{
		Finding: evaluation.Finding{
			ControlID: "CTL.S3.PUBLIC.001",
			AssetID:   "bucket-1",
		},
	}
	// Should not panic with nil Source, SourceEvidence, RemediationPlan
	sanitized := f.Sanitized(stubSanitizer{})
	if sanitized.AssetID == "bucket-1" {
		t.Fatal("AssetID should be sanitized")
	}
}

// ---------------------------------------------------------------------------
// Planner
// ---------------------------------------------------------------------------

func TestPlannerPlanFor_PublicExposure(t *testing.T) {
	p := NewPlanner(stubIDGen{})
	f := Finding{
		Finding: evaluation.Finding{
			ControlID: "CTL.S3.PUBLIC.001",
			AssetID:   "bucket-1",
			AssetType: "aws_s3_bucket",
		},
	}
	plan := p.PlanFor(f)
	if plan == nil {
		t.Fatal("expected plan for public exposure")
	}
	if len(plan.Actions) == 0 {
		t.Fatal("expected actions")
	}
	if plan.Target.AssetID != "bucket-1" {
		t.Fatalf("Target.AssetID = %v", plan.Target.AssetID)
	}
}

func TestPlannerPlanFor_UnknownClass(t *testing.T) {
	p := NewPlanner(stubIDGen{})
	f := Finding{
		Finding: evaluation.Finding{
			ControlID: "CTL.CUSTOM.UNKNOWN.001",
			AssetID:   "res-1",
		},
	}
	plan := p.PlanFor(f)
	if plan != nil {
		t.Fatal("unknown class should return nil plan")
	}
}

// ---------------------------------------------------------------------------
// publicExposurePlanner
// ---------------------------------------------------------------------------

func TestPublicExposurePlannerCanHandle(t *testing.T) {
	p := publicExposurePlanner{}
	if !p.CanHandle(kernel.ClassPublicExposure) {
		t.Fatal("should handle ClassPublicExposure")
	}
	if p.CanHandle(kernel.ClassEncryptionMissing) {
		t.Fatal("should not handle ClassEncryptionMissing")
	}
}

func TestPublicExposurePlannerPlan(t *testing.T) {
	p := publicExposurePlanner{idGen: stubIDGen{}}
	f := Finding{
		Finding: evaluation.Finding{
			ControlID: "CTL.S3.PUBLIC.001",
			AssetID:   "bucket-1",
			AssetType: "aws_s3_bucket",
		},
	}
	plan := p.Plan(f)
	if plan == nil {
		t.Fatal("expected plan")
	}
	if len(plan.Actions) != 4 {
		t.Fatalf("expected 4 actions, got %d", len(plan.Actions))
	}
	if len(plan.Preconditions) != 2 {
		t.Fatalf("expected 2 preconditions, got %d", len(plan.Preconditions))
	}
	// Actions should be sorted by path
	for i := 1; i < len(plan.Actions); i++ {
		if plan.Actions[i].Path < plan.Actions[i-1].Path {
			t.Fatal("actions should be sorted by path")
		}
	}
}

// ---------------------------------------------------------------------------
// GroupStats
// ---------------------------------------------------------------------------

func TestGroupStats(t *testing.T) {
	groups := []Group{
		{FindingCount: 3},
		{FindingCount: 1},
		{FindingCount: 2},
	}
	total, hasMulti := GroupStats(groups)
	if total != 6 {
		t.Fatalf("total = %d", total)
	}
	if !hasMulti {
		t.Fatal("should have multi")
	}

	single := []Group{{FindingCount: 1}}
	total, hasMulti = GroupStats(single)
	if total != 1 || hasMulti {
		t.Fatalf("total=%d, hasMulti=%v", total, hasMulti)
	}
}

// ---------------------------------------------------------------------------
// BaselineEntriesFromFindings
// ---------------------------------------------------------------------------

func TestBaselineEntriesFromFindings(t *testing.T) {
	findings := []Finding{
		{Finding: evaluation.Finding{ControlID: "CTL.B.001", ControlName: "B", AssetID: "res-2", AssetType: "bucket"}},
		{Finding: evaluation.Finding{ControlID: "CTL.A.001", ControlName: "A", AssetID: "res-1", AssetType: "bucket"}},
		{Finding: evaluation.Finding{ControlID: "CTL.A.001", ControlName: "A", AssetID: "res-1", AssetType: "bucket"}}, // duplicate
	}

	entries := BaselineEntriesFromFindings(findings)
	if len(entries) != 2 {
		t.Fatalf("expected 2 deduped entries, got %d", len(entries))
	}
	if entries[0].ControlID != "CTL.A.001" {
		t.Fatalf("first = %v, want CTL.A.001", entries[0].ControlID)
	}
	if entries[1].ControlID != "CTL.B.001" {
		t.Fatalf("second = %v, want CTL.B.001", entries[1].ControlID)
	}
}

func TestBaselineEntriesFromFindingsEmpty(t *testing.T) {
	if got := BaselineEntriesFromFindings(nil); got != nil {
		t.Fatalf("nil should return nil, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// buildNextSteps
// ---------------------------------------------------------------------------

func TestBuildNextSteps(t *testing.T) {
	d := &evaluation.FindingDetail{
		Remediation: &policy.RemediationSpec{Action: "do something"},
		Control:     evaluation.FindingControlSummary{ID: "CTL.TEST.001"},
	}
	steps := buildNextSteps(d)
	if len(steps) != 3 {
		t.Fatalf("expected 3 steps, got %d: %v", len(steps), steps)
	}
	if steps[0] != "Apply the remediation action described above." {
		t.Fatalf("[0] = %q", steps[0])
	}
}

func TestBuildNextSteps_NoAction(t *testing.T) {
	d := &evaluation.FindingDetail{
		Remediation: &policy.RemediationSpec{},
		Control:     evaluation.FindingControlSummary{ID: "CTL.TEST.001"},
	}
	steps := buildNextSteps(d)
	if len(steps) != 2 {
		t.Fatalf("expected 2 steps (no action), got %d: %v", len(steps), steps)
	}
}

// ---------------------------------------------------------------------------
// buildControlSummary
// ---------------------------------------------------------------------------

func TestBuildControlSummary_WithCtl(t *testing.T) {
	ctl := &policy.ControlDefinition{
		ID:          "CTL.TEST.001",
		Name:        "test",
		Description: "desc",
		Severity:    policy.SeverityHigh,
		Domain:      "storage",
		Type:        policy.TypeUnsafeState,
		ScopeTags:   []string{"s3"},
		Compliance:  policy.ComplianceMapping{"hipaa": "164.312"},
	}
	f := &evaluation.Finding{ControlID: "CTL.TEST.001"}
	s := buildControlSummary(ctl, f)
	if s.ID != "CTL.TEST.001" {
		t.Fatalf("ID = %v", s.ID)
	}
	if s.Domain != "storage" {
		t.Fatalf("Domain = %q", s.Domain)
	}
	if s.Type != "unsafe_state" {
		t.Fatalf("Type = %q", s.Type)
	}
}

func TestBuildControlSummary_NilCtl(t *testing.T) {
	f := &evaluation.Finding{
		ControlID:          "CTL.TEST.001",
		ControlName:        "fallback name",
		ControlDescription: "fallback desc",
		ControlSeverity:    policy.SeverityMedium,
	}
	s := buildControlSummary(nil, f)
	if s.Name != "fallback name" {
		t.Fatalf("Name = %q", s.Name)
	}
	if s.Severity != policy.SeverityMedium {
		t.Fatalf("Severity = %v", s.Severity)
	}
}

// ---------------------------------------------------------------------------
// StablePlanID
// ---------------------------------------------------------------------------

func TestStablePlanID(t *testing.T) {
	id := StablePlanID(stubIDGen{}, "CTL.TEST.001", "bucket-1")
	if id == "" {
		t.Fatal("should not be empty")
	}
}
