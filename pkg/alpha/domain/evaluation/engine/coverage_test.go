package engine

import (
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
)

func TestCoverageValidatorIsSufficient(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	t.Run("no coverage data", func(t *testing.T) {
		timeline := asset.NewTimeline(asset.Asset{ID: "res-1"})
		v := CoverageValidator{
			MinRequiredSpan: 24 * time.Hour,
			MaxAllowedGap:   12 * time.Hour,
		}
		reason, ok := v.IsSufficient(timeline)
		if ok {
			t.Fatal("expected ok=false")
		}
		if reason != "no observation snapshots found" {
			t.Fatalf("reason=%q, want %q", reason, "no observation snapshots found")
		}
	})

	t.Run("coverage span below required threshold", func(t *testing.T) {
		timeline := asset.NewTimeline(asset.Asset{ID: "res-1"})
		timeline.RecordObservation(base, false)
		timeline.RecordObservation(base.Add(6*time.Hour), false)

		v := CoverageValidator{
			MinRequiredSpan: 24 * time.Hour,
			MaxAllowedGap:   12 * time.Hour,
		}
		reason, ok := v.IsSufficient(timeline)
		if ok {
			t.Fatal("expected ok=false")
		}
		if !strings.Contains(reason, "observation span") || !strings.Contains(reason, "less than required") {
			t.Fatalf("unexpected reason: %q", reason)
		}
	})

	t.Run("max gap exceeds threshold", func(t *testing.T) {
		timeline := asset.NewTimeline(asset.Asset{ID: "res-1"})
		timeline.RecordObservation(base, false)
		timeline.RecordObservation(base.Add(13*time.Hour), false)
		timeline.RecordObservation(base.Add(26*time.Hour), false)

		v := CoverageValidator{
			MinRequiredSpan: 24 * time.Hour,
			MaxAllowedGap:   12 * time.Hour,
		}
		reason, ok := v.IsSufficient(timeline)
		if ok {
			t.Fatal("expected ok=false")
		}
		if !strings.Contains(reason, "maximum observation gap") || !strings.Contains(reason, "exceeds threshold") {
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
			MinRequiredSpan: 24 * time.Hour,
			MaxAllowedGap:   12 * time.Hour,
		}
		reason, ok := v.IsSufficient(timeline)
		if !ok {
			t.Fatalf("expected ok=true, got reason=%q", reason)
		}
		if reason != "" {
			t.Fatalf("reason=%q, want empty", reason)
		}
	})

	t.Run("nil timeline", func(t *testing.T) {
		v := CoverageValidator{
			MinRequiredSpan: 24 * time.Hour,
		}
		reason, ok := v.IsSufficient(nil)
		if ok {
			t.Fatal("expected ok=false for nil timeline")
		}
		if reason != "no timeline data provided" {
			t.Fatalf("reason=%q, want %q", reason, "no timeline data provided")
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
