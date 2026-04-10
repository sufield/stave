package engine

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func exposureControl(id string, protected, allowed []string) *policy.ControlDefinition {
	params := policy.ControlParams{}
	params.Set("protected_prefixes", protected)
	if len(allowed) > 0 {
		params.Set("allowed_public_prefixes", allowed)
	}
	ctl := &policy.ControlDefinition{
		ID:     kernel.ControlID(id),
		Name:   id,
		Type:   policy.TypePrefixExposure,
		Params: params,
	}
	_ = ctl.Prepare()
	return ctl
}

func exposureLifecycle(t *testing.T, props map[string]any) *asset.ExposureLifecycle {
	t.Helper()
	a := asset.Asset{
		ID:         "bucket-1",
		Type:       kernel.AssetType("s3_bucket"),
		Properties: props,
	}
	tl := asset.NewExposureLifecycle(a)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := tl.RecordCheck(base, false); err != nil {
		t.Fatalf("RecordObservation: %v", err)
	}
	return tl
}

// ---------------------------------------------------------------------------
// EvaluatePrefixExposureForRow
// ---------------------------------------------------------------------------

func TestExposure_MissingProtectedPrefixes(t *testing.T) {
	// Control with no protected_prefixes → config issue → violation
	ctl := exposureControl("CTL.EXP.001", nil, nil)
	tl := exposureLifecycle(t, nil)

	row, findings := EvaluatePrefixExposureForRow(tl, ctl)
	if row.Verdict != evaluation.VerdictViolation {
		t.Fatalf("expected Violation for missing protected prefixes, got %v", row.Verdict)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

func TestExposure_OverlappingPrefixes(t *testing.T) {
	// Allowed prefix overlaps with protected → config issue → violation
	ctl := exposureControl("CTL.EXP.001",
		[]string{"public/images"},
		[]string{"public/images/secret"},
	)
	tl := exposureLifecycle(t, nil)

	row, findings := EvaluatePrefixExposureForRow(tl, ctl)
	if row.Verdict != evaluation.VerdictViolation {
		t.Fatalf("expected Violation for overlapping prefixes, got %v", row.Verdict)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

func TestExposure_NoEvidence_IsViolation(t *testing.T) {
	// Missing exposure evidence is security-conservative → violation
	ctl := exposureControl("CTL.EXP.001", []string{"data/sensitive"}, nil)
	tl := exposureLifecycle(t, map[string]any{})

	row, findings := EvaluatePrefixExposureForRow(tl, ctl)
	if row.Verdict != evaluation.VerdictViolation {
		t.Fatalf("expected Violation for missing evidence, got %v", row.Verdict)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings for missing evidence")
	}
}

// ---------------------------------------------------------------------------
// prefixExposureStrategy (via strategy interface)
// ---------------------------------------------------------------------------

func TestPrefixExposureStrategy_Evaluate_ConfigIssue(t *testing.T) {
	// Verify the strategy delegates to EvaluatePrefixExposureForRow
	ctl := exposureControl("CTL.EXP.001", nil, nil) // no protected prefixes
	tl := exposureLifecycle(t, map[string]any{})
	now := time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC)

	s := &prefixExposureStrategy{ctl: ctl}
	row, findings := s.Evaluate(tl, now, nil)

	if row.Verdict != evaluation.VerdictViolation {
		t.Fatalf("expected Violation for config issue, got %v", row.Verdict)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func TestNewPrefixExposureRow(t *testing.T) {
	ctl := exposureControl("CTL.EXP.001", nil, nil)
	tl := exposureLifecycle(t, nil)

	row := newPrefixExposureRow(tl, ctl)
	if row.ControlID != "CTL.EXP.001" {
		t.Fatalf("ControlID = %v", row.ControlID)
	}
	if row.AssetID != "bucket-1" {
		t.Fatalf("AssetID = %v", row.AssetID)
	}
	if row.Verdict != evaluation.VerdictPass {
		t.Fatalf("default decision should be Pass, got %v", row.Verdict)
	}
}

func TestMsgMissingProtectedPrefixes(t *testing.T) {
	msg := msgMissingProtectedPrefixes()
	if msg == "" {
		t.Fatal("expected non-empty message")
	}
}
