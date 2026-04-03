package remediation

import (
	"testing"

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

// ---------------------------------------------------------------------------
// resolveSpec
// ---------------------------------------------------------------------------

func TestResolveSpec_YAMLDefinedRemediation(t *testing.T) {
	spec := &policy.RemediationSpec{
		Description: "custom desc",
		Action:      "custom action",
	}
	f := evaluation.Finding{
		ControlRemediation: spec,
	}
	got := resolveSpec(f)
	if got.Description != "custom desc" {
		t.Fatalf("Description = %q", got.Description)
	}
	if got.Action != "custom action" {
		t.Fatalf("Action = %q", got.Action)
	}
}

func TestResolveSpec_PublicExposureFallback(t *testing.T) {
	f := evaluation.Finding{
		ControlID: "CTL.S3.PUBLIC.001",
	}
	got := resolveSpec(f)
	if got.Description != "Resource is exposed to the public internet." {
		t.Fatalf("Description = %q", got.Description)
	}
}

func TestResolveSpec_EncryptionFallback(t *testing.T) {
	f := evaluation.Finding{
		ControlID: "CTL.S3.ENCRYPT.001",
	}
	got := resolveSpec(f)
	if got.Description != "Resource data is not encrypted at rest." {
		t.Fatalf("Description = %q", got.Description)
	}
}

func TestResolveSpec_BaselineFallback(t *testing.T) {
	// CTL.CUSTOM.001 matches ClassBaselineViolation (CTL.* prefix)
	f := evaluation.Finding{
		ControlID: "CTL.CUSTOM.001",
	}
	got := resolveSpec(f)
	if got.Description != "Resource configuration deviates from security baseline." {
		t.Fatalf("Description = %q", got.Description)
	}
}

func TestResolveSpec_DefaultFallback(t *testing.T) {
	// Non-CTL prefix triggers the default case
	f := evaluation.Finding{
		ControlID: "NONSTANDARD.001",
	}
	got := resolveSpec(f)
	if got.Description != "Security control violation detected." {
		t.Fatalf("Description = %q", got.Description)
	}
}

// ---------------------------------------------------------------------------
// Planner.EnrichFindings
// ---------------------------------------------------------------------------

func TestPlannerEnrichFindings(t *testing.T) {
	p := NewPlanner()
	result := evaluation.Result{
		Findings: []evaluation.Finding{
			{ControlID: "CTL.S3.PUBLIC.001", AssetID: "bucket-1", AssetType: "aws_s3_bucket"},
		},
	}
	enriched := p.EnrichFindings(result)
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
// Planner
// ---------------------------------------------------------------------------

func TestPlannerPlanFor_PublicExposure(t *testing.T) {
	p := NewPlanner()
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
	p := NewPlanner()
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
	p := publicExposurePlanner{}
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
		if plan.Actions[i].Path.String() < plan.Actions[i-1].Path.String() {
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
		ScopeTags:   []kernel.ScopeTag{"s3"},
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
	if s.Type != policy.TypeUnsafeState {
		t.Fatalf("Type = %v", s.Type)
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
// StableRemediationPlanID (via controldef)
// ---------------------------------------------------------------------------

func TestStableRemediationPlanID(t *testing.T) {
	id := policy.StableRemediationPlanID(stubIDGen{}, "CTL.TEST.001", "bucket-1")
	if id == "" {
		t.Fatal("should not be empty")
	}
}
