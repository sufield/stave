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

func exposureTimeline(t *testing.T, props map[string]any) *asset.Timeline {
	t.Helper()
	a := asset.Asset{
		ID:         "bucket-1",
		Type:       kernel.AssetType("s3_bucket"),
		Properties: props,
	}
	tl, err := asset.NewTimeline(a)
	if err != nil {
		t.Fatalf("NewTimeline: %v", err)
	}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := tl.RecordObservation(base, false); err != nil {
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
	tl := exposureTimeline(t, nil)
	now := time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC)

	row, findings := EvaluatePrefixExposureForRow(tl, ctl, now)
	if row.Decision != evaluation.DecisionViolation {
		t.Fatalf("expected Violation for missing protected prefixes, got %v", row.Decision)
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
	tl := exposureTimeline(t, nil)
	now := time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC)

	row, findings := EvaluatePrefixExposureForRow(tl, ctl, now)
	if row.Decision != evaluation.DecisionViolation {
		t.Fatalf("expected Violation for overlapping prefixes, got %v", row.Decision)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

func TestExposure_NoEvidence_IsViolation(t *testing.T) {
	// Missing exposure evidence is security-conservative → violation
	ctl := exposureControl("CTL.EXP.001", []string{"data/sensitive"}, nil)
	tl := exposureTimeline(t, map[string]any{})
	now := time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC)

	row, findings := EvaluatePrefixExposureForRow(tl, ctl, now)
	if row.Decision != evaluation.DecisionViolation {
		t.Fatalf("expected Violation for missing evidence, got %v", row.Decision)
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
	tl := exposureTimeline(t, map[string]any{})
	now := time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC)

	s := &prefixExposureStrategy{ctl: ctl}
	row, findings := s.Evaluate(tl, now)

	if row.Decision != evaluation.DecisionViolation {
		t.Fatalf("expected Violation for config issue, got %v", row.Decision)
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
	tl := exposureTimeline(t, nil)

	row := newPrefixExposureRow(tl, ctl)
	if row.ControlID != "CTL.EXP.001" {
		t.Fatalf("ControlID = %v", row.ControlID)
	}
	if row.AssetID != "bucket-1" {
		t.Fatalf("AssetID = %v", row.AssetID)
	}
	if row.Decision != evaluation.DecisionPass {
		t.Fatalf("default decision should be Pass, got %v", row.Decision)
	}
}

func TestMsgMissingProtectedPrefixes(t *testing.T) {
	msg := msgMissingProtectedPrefixes()
	if msg == "" {
		t.Fatal("expected non-empty message")
	}
}
