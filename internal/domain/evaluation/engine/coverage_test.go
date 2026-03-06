package engine

import (
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
)

func TestCoverageValidatorValidate(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	t.Run("no coverage data", func(t *testing.T) {
		timeline := asset.NewTimeline(asset.Asset{ID: "res-1"})
		v := CoverageValidator{
			Timeline:         timeline,
			RequiredCoverage: 24 * time.Hour,
			MaxGapThreshold:  12 * time.Hour,
			CoverageReason:   "coverage too short",
		}
		reason, inconclusive := v.Validate()
		if !inconclusive {
			t.Fatal("expected inconclusive=true")
		}
		if reason != "no coverage data" {
			t.Fatalf("reason=%q, want %q", reason, "no coverage data")
		}
	})

	t.Run("coverage span below required threshold", func(t *testing.T) {
		timeline := asset.NewTimeline(asset.Asset{ID: "res-1"})
		timeline.RecordObservation(base, false)
		timeline.RecordObservation(base.Add(6*time.Hour), false)

		v := CoverageValidator{
			Timeline:         timeline,
			RequiredCoverage: 24 * time.Hour,
			MaxGapThreshold:  12 * time.Hour,
			CoverageReason:   "coverage span less than required threshold",
		}
		reason, inconclusive := v.Validate()
		if !inconclusive {
			t.Fatal("expected inconclusive=true")
		}
		if reason != "coverage span less than required threshold" {
			t.Fatalf("reason=%q, want coverage reason", reason)
		}
	})

	t.Run("max gap exceeds threshold", func(t *testing.T) {
		timeline := asset.NewTimeline(asset.Asset{ID: "res-1"})
		timeline.RecordObservation(base, false)
		timeline.RecordObservation(base.Add(13*time.Hour), false)
		timeline.RecordObservation(base.Add(26*time.Hour), false)

		v := CoverageValidator{
			Timeline:         timeline,
			RequiredCoverage: 24 * time.Hour,
			MaxGapThreshold:  12 * time.Hour,
			CoverageReason:   "coverage span less than required threshold",
		}
		reason, inconclusive := v.Validate()
		if !inconclusive {
			t.Fatal("expected inconclusive=true")
		}
		if !strings.Contains(reason, "observation gap exceeds 12h") {
			t.Fatalf("unexpected reason: %q", reason)
		}
	})

	t.Run("coverage sufficient", func(t *testing.T) {
		timeline := asset.NewTimeline(asset.Asset{ID: "res-1"})
		timeline.RecordObservation(base, false)
		timeline.RecordObservation(base.Add(10*time.Hour), false)
		timeline.RecordObservation(base.Add(20*time.Hour), false)
		timeline.RecordObservation(base.Add(30*time.Hour), false)

		v := CoverageValidator{
			Timeline:         timeline,
			RequiredCoverage: 24 * time.Hour,
			MaxGapThreshold:  12 * time.Hour,
			CoverageReason:   "coverage span less than required threshold",
		}
		reason, inconclusive := v.Validate()
		if inconclusive {
			t.Fatalf("expected inconclusive=false, got reason=%q", reason)
		}
		if reason != "" {
			t.Fatalf("reason=%q, want empty", reason)
		}
	})
}

func TestEvaluationRowMarkInconclusive(t *testing.T) {
	row := evaluation.Row{
		Decision:   evaluation.DecisionPass,
		Confidence: evaluation.ConfidenceHigh,
	}
	row.MarkInconclusive("insufficient observations")
	if row.Decision != evaluation.DecisionInconclusive {
		t.Fatalf("decision=%s, want %s", row.Decision, evaluation.DecisionInconclusive)
	}
	if row.Confidence != evaluation.ConfidenceInconclusive {
		t.Fatalf("confidence=%s, want %s", row.Confidence, evaluation.ConfidenceInconclusive)
	}
	if row.Reason != "insufficient observations" {
		t.Fatalf("reason=%q, want %q", row.Reason, "insufficient observations")
	}
}
