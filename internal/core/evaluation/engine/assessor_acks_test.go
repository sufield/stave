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
// when a different asset B has CTL.Y failing. The earlier shape used
// a single global "any failure of CTL.Y" set, so B's failure
// invalidated A's acknowledgment despite A's compensating control
// being healthy on its own asset.
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
		{FindingID: "f2", ControlID: "CTL.Y", AssetID: asset.ID("asset-B")}, // B fails CTL.Y
	}

	// CTL.Y was evaluated on asset-A (the absence of a finding for it
	// is what we want to count as "passing"). The new "unevaluated"
	// status fires only when a compensating control was never
	// evaluated; EvaluationCoverage distinguishes those two cases.
	coverage := EvaluationCoverage{
		"asset-A": {"CTL.X": true, "CTL.Y": true},
		"asset-B": {"CTL.Y": true},
	}

	active, ackd := applyAcknowledgments(findings, nil, acks, now, coverage)

	// A's ack for CTL.X must be valid: CTL.Y passes on A.
	if len(ackd) != 1 {
		t.Fatalf("expected 1 acknowledged finding, got %d", len(ackd))
	}
	if !ackd[0].Valid {
		t.Errorf("A's acknowledgment must remain valid; got InvalidReason=%q",
			ackd[0].InvalidReason)
	}
	// B's CTL.Y finding stays active (no ack covers it).
	if len(active) != 1 {
		t.Fatalf("expected 1 active finding, got %d", len(active))
	}
	if active[0].FindingID != "f2" {
		t.Errorf("active finding = %s, want f2", active[0].FindingID)
	}
}

// TestApplyAcknowledgments_AckInvalidatedByOwnAssetFailure confirms
// the partitioning still rejects the ack when the same asset's own
// compensating control is failing — that is the original intent of
// the compensating-control check, and we must not regress it.
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
		{FindingID: "f2", ControlID: "CTL.Y", AssetID: asset.ID("asset-A")}, // A's own CTL.Y fails
	}

	coverage := EvaluationCoverage{
		"asset-A": {"CTL.X": true, "CTL.Y": true},
	}

	_, ackd := applyAcknowledgments(findings, nil, acks, now, coverage)
	if len(ackd) != 1 {
		t.Fatalf("expected 1 acknowledged record, got %d", len(ackd))
	}
	if ackd[0].Valid {
		t.Error("ack must be invalid when own-asset compensating control fails")
	}
	if ackd[0].InvalidReason != "compensating_controls_failing" {
		t.Errorf("InvalidReason = %q, want compensating_controls_failing",
			ackd[0].InvalidReason)
	}
}
