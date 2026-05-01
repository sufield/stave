package engine

import (
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
)

func TestCoverageValidatorIsSufficient(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	t.Run("no coverage data", func(t *testing.T) {
		lifecycle, _ := asset.NewExposureLifecycle(asset.Asset{ID: "res-1"})
		v := CoverageValidator{
			minRequiredSpan: 24 * time.Hour,
			maxAllowedGap:   12 * time.Hour,
		}
		reason, ok := v.IsSufficient(lifecycle)
		if ok {
			t.Fatal("expected ok=false")
		}
		if reason != "no observation snapshots found" {
			t.Fatalf("reason=%q, want %q", reason, "no observation snapshots found")
		}
	})

	t.Run("coverage span below required threshold", func(t *testing.T) {
		lifecycle, _ := asset.NewExposureLifecycle(asset.Asset{ID: "res-1"})
		if err := lifecycle.RecordCheck(base, false); err != nil {
			t.Fatal(err)
		}
		if err := lifecycle.RecordCheck(base.Add(6*time.Hour), false); err != nil {
			t.Fatal(err)
		}

		v := CoverageValidator{
			minRequiredSpan: 24 * time.Hour,
			maxAllowedGap:   12 * time.Hour,
		}
		reason, ok := v.IsSufficient(lifecycle)
		if ok {
			t.Fatal("expected ok=false")
		}
		if !strings.Contains(reason, "observation span") || !strings.Contains(reason, "less than required") {
			t.Fatalf("unexpected reason: %q", reason)
		}
	})

	t.Run("max gap exceeds threshold", func(t *testing.T) {
		lifecycle, _ := asset.NewExposureLifecycle(asset.Asset{ID: "res-1"})
		if err := lifecycle.RecordCheck(base, false); err != nil {
			t.Fatal(err)
		}
		if err := lifecycle.RecordCheck(base.Add(13*time.Hour), false); err != nil {
			t.Fatal(err)
		}
		if err := lifecycle.RecordCheck(base.Add(26*time.Hour), false); err != nil {
			t.Fatal(err)
		}

		v := CoverageValidator{
			minRequiredSpan: 24 * time.Hour,
			maxAllowedGap:   12 * time.Hour,
		}
		reason, ok := v.IsSufficient(lifecycle)
		if ok {
			t.Fatal("expected ok=false")
		}
		if !strings.Contains(reason, "maximum observation gap") || !strings.Contains(reason, "exceeds threshold") {
			t.Fatalf("unexpected reason: %q", reason)
		}
	})

	t.Run("coverage sufficient", func(t *testing.T) {
		lifecycle, _ := asset.NewExposureLifecycle(asset.Asset{ID: "res-1"})
		if err := lifecycle.RecordCheck(base, false); err != nil {
			t.Fatal(err)
		}
		if err := lifecycle.RecordCheck(base.Add(10*time.Hour), false); err != nil {
			t.Fatal(err)
		}
		if err := lifecycle.RecordCheck(base.Add(20*time.Hour), false); err != nil {
			t.Fatal(err)
		}
		if err := lifecycle.RecordCheck(base.Add(30*time.Hour), false); err != nil {
			t.Fatal(err)
		}

		v := CoverageValidator{
			minRequiredSpan: 24 * time.Hour,
			maxAllowedGap:   12 * time.Hour,
		}
		reason, ok := v.IsSufficient(lifecycle)
		if !ok {
			t.Fatalf("expected ok=true, got reason=%q", reason)
		}
		if reason != "" {
			t.Fatalf("reason=%q, want empty", reason)
		}
	})

	t.Run("nil lifecycle", func(t *testing.T) {
		v := CoverageValidator{
			minRequiredSpan: 24 * time.Hour,
		}
		reason, ok := v.IsSufficient(nil)
		if ok {
			t.Fatal("expected ok=false for nil lifecycle")
		}
		if reason != "no lifecycle data provided" {
			t.Fatalf("reason=%q, want %q", reason, "no lifecycle data provided")
		}
	})
}

func TestEvaluationRowMarkInconclusive(t *testing.T) {
	row := evaluation.ResourceCheck{
		Verdict:    evaluation.VerdictPass,
		Confidence: evaluation.ConfidenceHigh,
	}
	row.MarkInconclusive("insufficient observations")
	if row.Verdict != evaluation.VerdictInconclusive {
		t.Fatalf("decision=%s, want %s", row.Verdict, evaluation.VerdictInconclusive)
	}
	if row.Confidence != evaluation.ConfidenceInconclusive {
		t.Fatalf("confidence=%s, want %s", row.Confidence, evaluation.ConfidenceInconclusive)
	}
	if row.Reason != "insufficient observations" {
		t.Fatalf("reason=%q, want %q", row.Reason, "insufficient observations")
	}
}
