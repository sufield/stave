package engine

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

// TestApplyAcknowledgments_AssetAAckSurvivesAssetBFailure pins the
// per-asset partitioning fix: an acknowledgment for (CTL.X, A) whose
// compensating control CTL.Y is passing on A must remain valid even
// when a different asset B has CTL.Y failing.
func TestApplyAcknowledgments_AssetAAckSurvivesAssetBFailure(t *testing.T) {
	now := time.Now()

	acks := policy.NewAcknowledgmentConfig([]policy.AcknowledgmentRule{
		{
			ControlID:            "CTL.X",
			AssetID:              "asset-A",
			Rationale:            "compensated on A",
			AcknowledgedBy:       "ops@example.com",
			AcknowledgedDate:     "2026-01-01",
			CompensatingControls: []kernel.ControlID{"CTL.Y"},
		},
	})

	findings := []evaluation.Finding{
		{FindingID: "f1", ControlID: "CTL.X", AssetID: asset.ID("asset-A")},
		{FindingID: "f2", ControlID: "CTL.Y", AssetID: asset.ID("asset-B")},
	}

	coverage := EvaluationCoverage{
		"asset-A": {"CTL.X": {}, "CTL.Y": {}},
		"asset-B": {"CTL.Y": {}},
	}

	result := applyAcknowledgments(findings, nil, acks, now, coverage)

	// A's CTL.X should be suppressed (valid ack).
	var suppressed, active []evaluation.Finding
	for _, f := range result {
		if f.Status == evaluation.FindingSuppressed {
			suppressed = append(suppressed, f)
		} else {
			active = append(active, f)
		}
	}

	if len(suppressed) != 1 {
		t.Fatalf("expected 1 suppressed finding, got %d", len(suppressed))
	}
	if suppressed[0].Suppression == nil || !suppressed[0].Suppression.Valid {
		t.Error("A's acknowledgment must remain valid")
	}
	if len(active) != 1 {
		t.Fatalf("expected 1 active finding, got %d", len(active))
	}
	if active[0].FindingID != "f2" {
		t.Errorf("active finding = %s, want f2", active[0].FindingID)
	}
}

// TestApplyAcknowledgments_AckInvalidatedByOwnAssetFailure confirms
// the ack is rejected when the same asset's compensating control fails.
func TestApplyAcknowledgments_AckInvalidatedByOwnAssetFailure(t *testing.T) {
	now := time.Now()

	acks := policy.NewAcknowledgmentConfig([]policy.AcknowledgmentRule{
		{
			ControlID:            "CTL.X",
			AssetID:              "asset-A",
			Rationale:            "compensated on A",
			AcknowledgedBy:       "ops@example.com",
			AcknowledgedDate:     "2026-01-01",
			CompensatingControls: []kernel.ControlID{"CTL.Y"},
		},
	})

	findings := []evaluation.Finding{
		{FindingID: "f1", ControlID: "CTL.X", AssetID: asset.ID("asset-A")},
		{FindingID: "f2", ControlID: "CTL.Y", AssetID: asset.ID("asset-A")},
	}

	coverage := EvaluationCoverage{
		"asset-A": {"CTL.X": {}, "CTL.Y": {}},
	}

	result := applyAcknowledgments(findings, nil, acks, now, coverage)

	var suppressed []evaluation.Finding
	for _, f := range result {
		if f.Status == evaluation.FindingSuppressed {
			suppressed = append(suppressed, f)
		}
	}

	if len(suppressed) != 1 {
		t.Fatalf("expected 1 suppressed record, got %d", len(suppressed))
	}
	if suppressed[0].Suppression == nil || suppressed[0].Suppression.Valid {
		t.Error("ack must be invalid when own-asset compensating control fails")
	}
	if suppressed[0].Suppression.InvalidReason != "compensating_controls_failing" {
		t.Errorf("InvalidReason = %q, want compensating_controls_failing",
			suppressed[0].Suppression.InvalidReason)
	}
}
