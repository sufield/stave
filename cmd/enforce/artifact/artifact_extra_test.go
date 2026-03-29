package artifact

import (
	"context"
	"testing"

	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/sanitize"
)

func TestNewLoader(t *testing.T) {
	l := NewLoader()
	if l == nil {
		t.Fatal("expected non-nil loader")
	}
}

func TestLoader_Evaluation_EmptyPath(t *testing.T) {
	l := NewLoader()
	_, err := l.Evaluation(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestLoader_Baseline_EmptyPath(t *testing.T) {
	l := NewLoader()
	_, err := l.Baseline(context.Background(), "", kernel.KindBaseline)
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestCompareAgainstBaseline_NilSanitizer(t *testing.T) {
	base := []evaluation.BaselineEntry{
		{ControlID: "CTL.A", AssetID: "res-1"},
	}
	current := []remediation.Finding{
		{Finding: evaluation.Finding{ControlID: "CTL.A", AssetID: "res-1"}},
	}
	result := CompareAgainstBaseline(nil, base, current)
	if len(result.Comparison.New) != 0 {
		t.Fatalf("expected 0 new, got %d", len(result.Comparison.New))
	}
}

func TestCompareAgainstBaseline_WithSanitizer(t *testing.T) {
	san := sanitize.New(sanitize.WithIDSanitization(true))
	base := []evaluation.BaselineEntry{
		{ControlID: "CTL.A", AssetID: "res-1"},
	}
	current := []remediation.Finding{
		{Finding: evaluation.Finding{ControlID: "CTL.B", AssetID: "res-2"}},
	}
	result := CompareAgainstBaseline(san, base, current)
	if len(result.Comparison.New) != 1 {
		t.Fatalf("expected 1 new, got %d", len(result.Comparison.New))
	}
	if len(result.Comparison.Resolved) != 1 {
		t.Fatalf("expected 1 resolved, got %d", len(result.Comparison.Resolved))
	}
}
