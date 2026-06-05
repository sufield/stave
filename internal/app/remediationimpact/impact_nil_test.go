package remediationimpact

import (
	"testing"

	"github.com/sufield/stave/internal/core/report"
)

// Bug 2 — Analyze dereferences in.Before / in.After throughout, and
// computeSimpleScore reads a.Summary.TotalAssets, both without a nil guard.
// A nil input must surface as a returned error (Analyze) or a sentinel value
// (computeSimpleScore), never a panic that aborts the whole package run.

func TestAnalyze_NilBefore_ReturnsErrorNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Analyze panicked on nil Before (missing nil guard): %v", r)
		}
	}()

	if _, err := Analyze(Input{Before: nil, After: &report.Assessment{}}); err == nil {
		t.Fatal("Analyze accepted nil Before without returning an error")
	}
}

func TestAnalyze_NilAfter_ReturnsErrorNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Analyze panicked on nil After (missing nil guard): %v", r)
		}
	}()

	if _, err := Analyze(Input{Before: &report.Assessment{}, After: nil}); err == nil {
		t.Fatal("Analyze accepted nil After without returning an error")
	}
}

func TestComputeSimpleScore_Nil_NoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("computeSimpleScore panicked on nil assessment: %v", r)
		}
	}()

	if got := computeSimpleScore(nil); got != 0 {
		t.Errorf("computeSimpleScore(nil) = %v, want 0 (no-data sentinel)", got)
	}
}
