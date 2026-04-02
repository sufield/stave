package remediation

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
)

// ---------------------------------------------------------------------------
// BuildGroups
// ---------------------------------------------------------------------------

func TestBuildGroups_Empty(t *testing.T) {
	groups := BuildGroups(stubDigester{}, stubIDGen{}, nil)
	if groups != nil {
		t.Fatalf("expected nil, got %v", groups)
	}
}

func TestBuildGroups_SingleFinding(t *testing.T) {
	findings := []Finding{
		{
			Finding: evaluation.Finding{
				ControlID: "CTL.A.001",
				AssetID:   "bucket-1",
				AssetType: "s3_bucket",
			},
			RemediationPlan: &evaluation.RemediationPlan{
				ID: "plan-1",
				Target: evaluation.RemediationTarget{
					AssetID:   "bucket-1",
					AssetType: "s3_bucket",
				},
				Actions: []evaluation.RemediationAction{
					{ActionType: evaluation.ActionSet, Path: predicate.NewFieldPath("public_access"), Value: false},
				},
			},
		},
	}

	groups := BuildGroups(stubDigester{}, stubIDGen{}, findings)
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	if groups[0].FindingCount != 1 {
		t.Fatalf("FindingCount = %d", groups[0].FindingCount)
	}
	if len(groups[0].ContributingControls) != 1 {
		t.Fatalf("ContributingControls = %v", groups[0].ContributingControls)
	}
}

func TestBuildGroups_MultipleFindingsSameAsset(t *testing.T) {
	plan := &evaluation.RemediationPlan{
		ID: "plan-1",
		Target: evaluation.RemediationTarget{
			AssetID:   "bucket-1",
			AssetType: "s3_bucket",
		},
		Actions: []evaluation.RemediationAction{
			{ActionType: evaluation.ActionSet, Path: predicate.NewFieldPath("public_access"), Value: false},
		},
	}

	findings := []Finding{
		{
			Finding: evaluation.Finding{
				ControlID: "CTL.A.001",
				AssetID:   "bucket-1",
				AssetType: "s3_bucket",
			},
			RemediationPlan: plan,
		},
		{
			Finding: evaluation.Finding{
				ControlID: "CTL.B.001",
				AssetID:   "bucket-1",
				AssetType: "s3_bucket",
			},
			RemediationPlan: plan,
		},
	}

	groups := BuildGroups(stubDigester{}, stubIDGen{}, findings)
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	if groups[0].FindingCount != 2 {
		t.Fatalf("FindingCount = %d", groups[0].FindingCount)
	}
	if len(groups[0].ContributingControls) != 2 {
		t.Fatalf("ContributingControls = %v", groups[0].ContributingControls)
	}
}

func TestBuildGroups_NilPlanSkipped(t *testing.T) {
	findings := []Finding{
		{
			Finding: evaluation.Finding{
				ControlID: "CTL.A.001",
				AssetID:   "bucket-1",
			},
			RemediationPlan: nil,
		},
	}

	groups := BuildGroups(stubDigester{}, stubIDGen{}, findings)
	if groups != nil {
		t.Fatalf("expected nil (no plans), got %v", groups)
	}
}

// ---------------------------------------------------------------------------
// GroupStats
// ---------------------------------------------------------------------------

func TestGroupStats_Empty(t *testing.T) {
	total, hasMulti := GroupStats(nil)
	if total != 0 || hasMulti {
		t.Fatalf("total=%d, hasMulti=%v", total, hasMulti)
	}
}

func TestGroupStats_WithMulti(t *testing.T) {
	groups := []Group{
		{FindingCount: 3},
		{FindingCount: 1},
	}
	total, hasMulti := GroupStats(groups)
	if total != 4 {
		t.Fatalf("total = %d", total)
	}
	if !hasMulti {
		t.Fatal("expected hasMulti=true")
	}
}

// ---------------------------------------------------------------------------
// BuildFindingDetail
// ---------------------------------------------------------------------------

type stubControlProvider struct {
	ctl *policy.ControlDefinition
}

func (p *stubControlProvider) FindByID(id kernel.ControlID) *policy.ControlDefinition {
	if p.ctl != nil && p.ctl.ID == id {
		return p.ctl
	}
	return nil
}

func TestBuildFindingDetail_NotFound(t *testing.T) {
	r := &evaluation.Result{}
	_, err := BuildFindingDetail(r, evaluation.FindingDetailRequest{
		ControlID: "CTL.NOPE",
		AssetID:   "bucket-nope",
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBuildFindingDetail_Found(t *testing.T) {
	ctl := &policy.ControlDefinition{
		ID:          "CTL.A.001",
		Name:        "Test Control",
		Description: "Test description",
		Severity:    policy.SeverityHigh,
		Domain:      "storage",
		Type:        policy.TypeUnsafeDuration,
		Exposure: &policy.Exposure{
			Type:           "public_read",
			PrincipalScope: kernel.ScopePublic,
		},
	}

	r := &evaluation.Result{
		Findings: []evaluation.Finding{
			{
				ControlID:          "CTL.A.001",
				ControlName:        "Test Control",
				ControlDescription: "Test description",
				AssetID:            "bucket-1",
				AssetType:          "s3_bucket",
				AssetVendor:        "aws",
				ControlSeverity:    policy.SeverityHigh,
				Evidence: evaluation.Evidence{
					WhyNow: "test",
				},
			},
		},
	}

	detail, err := BuildFindingDetail(r, evaluation.FindingDetailRequest{
		ControlID: "CTL.A.001",
		AssetID:   "bucket-1",
		Controls:  &stubControlProvider{ctl: ctl},
		IDGen:     stubIDGen{},
	})
	if err != nil {
		t.Fatalf("BuildFindingDetail: %v", err)
	}
	if detail.Control.ID != "CTL.A.001" {
		t.Fatalf("Control.ID = %v", detail.Control.ID)
	}
	if detail.Control.Domain != "storage" {
		t.Fatalf("Control.Domain = %v", detail.Control.Domain)
	}
	if detail.Remediation == nil {
		t.Fatal("expected remediation spec")
	}
	if len(detail.NextSteps) == 0 {
		t.Fatal("expected next steps")
	}
}

func TestBuildFindingDetail_NoControlProvider(t *testing.T) {
	r := &evaluation.Result{
		Findings: []evaluation.Finding{
			{
				ControlID:       "CTL.A.001",
				ControlName:     "Fallback Name",
				AssetID:         "bucket-1",
				ControlSeverity: policy.SeverityMedium,
			},
		},
	}

	detail, err := BuildFindingDetail(r, evaluation.FindingDetailRequest{
		ControlID: "CTL.A.001",
		AssetID:   "bucket-1",
		IDGen:     stubIDGen{},
	})
	if err != nil {
		t.Fatalf("BuildFindingDetail: %v", err)
	}
	// Should use fallback from finding data
	if detail.Control.Name != "Fallback Name" {
		t.Fatalf("Control.Name = %q", detail.Control.Name)
	}
}

// ---------------------------------------------------------------------------
// canonicalActionsHash
// ---------------------------------------------------------------------------

func TestCanonicalActionsHash_Empty(t *testing.T) {
	hash := canonicalActionsHash(stubDigester{}, nil)
	if hash != "" {
		t.Fatalf("empty actions should return empty hash, got %q", hash)
	}
}

func TestCanonicalActionsHash_NonEmpty(t *testing.T) {
	actions := []evaluation.RemediationAction{
		{ActionType: evaluation.ActionSet, Path: predicate.NewFieldPath("public_access"), Value: false},
	}
	hash := canonicalActionsHash(stubDigester{}, actions)
	if hash == "" {
		t.Fatal("expected non-empty hash")
	}
}

// ---------------------------------------------------------------------------
// sanitizeSlice
// ---------------------------------------------------------------------------

func TestSanitizeSlice_Empty(t *testing.T) {
	got := sanitizeSlice[kernel.StatementID](nil, stubSanitizer{})
	if got != nil {
		t.Fatal("nil should return nil")
	}
}

func TestSanitizeSlice_NonEmpty(t *testing.T) {
	items := []kernel.StatementID{"stmt-1", "stmt-2"}
	got := sanitizeSlice(items, stubSanitizer{})
	if len(got) != 2 {
		t.Fatalf("len = %d", len(got))
	}
	for _, v := range got {
		if v != "[REDACTED-VAL]" {
			t.Fatalf("expected redacted, got %q", v)
		}
	}
}

// ---------------------------------------------------------------------------
// Sanitized (Finding method)
// ---------------------------------------------------------------------------

func TestFinding_Sanitized_Full(t *testing.T) {
	f := Finding{
		Finding: evaluation.Finding{
			ControlID: "CTL.A.001",
			AssetID:   "bucket-secret",
			Source:    &asset.SourceRef{File: "/path/to/obs.json", Line: 42},
			Evidence: evaluation.Evidence{
				Misconfigurations: []policy.Misconfiguration{
					{Property: predicate.NewFieldPath("public_access"), ActualValue: true, Operator: "eq", UnsafeValue: true},
				},
				SourceEvidence: &evaluation.SourceEvidence{
					IdentityStatements: []kernel.StatementID{"stmt-1"},
					ResourceGrantees:   []kernel.GranteeID{"grant-1"},
				},
			},
		},
		RemediationPlan: &evaluation.RemediationPlan{
			ID: "plan-1",
			Target: evaluation.RemediationTarget{
				AssetID:   "bucket-secret",
				AssetType: "s3_bucket",
			},
		},
	}

	sanitized := f.Sanitized(stubSanitizer{})
	if sanitized.AssetID != "[REDACTED-ID]" {
		t.Fatalf("AssetID = %v", sanitized.AssetID)
	}
	if sanitized.Source.File != "[REDACTED-PATH]" {
		t.Fatalf("Source.File = %v", sanitized.Source.File)
	}
	if sanitized.RemediationPlan.Target.AssetID != "[REDACTED-ID]" {
		t.Fatalf("Plan.Target.AssetID = %v", sanitized.RemediationPlan.Target.AssetID)
	}
}
