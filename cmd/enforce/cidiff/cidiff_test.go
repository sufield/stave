package cidiff

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/sufield/stave/cmd/enforce/artifact"
	"github.com/sufield/stave/internal/safetyenvelope"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/remediation"
)

func writeEvalJSON(t *testing.T, dir, name string, violations []remediation.Finding) string {
	t.Helper()
	eval := safetyenvelope.Evaluation{
		Kind:     safetyenvelope.KindEvaluation,
		Findings: violations,
	}
	data, err := json.MarshalIndent(eval, "", "  ")
	if err != nil {
		t.Fatalf("marshal eval: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write eval: %v", err)
	}
	return path
}

func TestCIDiff_NewAndResolved(t *testing.T) {
	dir := t.TempDir()

	baselinePath := writeEvalJSON(t, dir, "baseline.json", []remediation.Finding{
		{Finding: evaluation.Finding{ControlID: "CTL.TEST.A.001", ControlName: "A", AssetID: "res-1", AssetType: "bucket"}},
		{Finding: evaluation.Finding{ControlID: "CTL.TEST.B.001", ControlName: "B", AssetID: "res-2", AssetType: "bucket"}},
	})

	currentPath := writeEvalJSON(t, dir, "current.json", []remediation.Finding{
		{Finding: evaluation.Finding{ControlID: "CTL.TEST.B.001", ControlName: "B", AssetID: "res-2", AssetType: "bucket"}},
		{Finding: evaluation.Finding{ControlID: "CTL.TEST.C.001", ControlName: "C", AssetID: "res-3", AssetType: "bucket"}},
	})

	// Load and compare using the same functions as runCIDiff
	baselineEval, err := artifact.NewLoader().Evaluation(context.Background(), baselinePath)
	if err != nil {
		t.Fatalf("load baseline: %v", err)
	}
	currentEval, err := artifact.NewLoader().Evaluation(context.Background(), currentPath)
	if err != nil {
		t.Fatalf("load current: %v", err)
	}

	baselineEntries := remediation.BaselineEntriesFromFindings(baselineEval.Findings)
	currentEntries := remediation.BaselineEntriesFromFindings(currentEval.Findings)
	comparison := evaluation.CompareBaseline(baselineEntries, currentEntries)

	if len(comparison.New) != 1 {
		t.Fatalf("expected 1 new finding, got %d", len(comparison.New))
	}
	if comparison.New[0].ControlID != "CTL.TEST.C.001" {
		t.Errorf("new finding: got %s, want CTL.TEST.C.001", comparison.New[0].ControlID)
	}

	if len(comparison.Resolved) != 1 {
		t.Fatalf("expected 1 resolved finding, got %d", len(comparison.Resolved))
	}
	if comparison.Resolved[0].ControlID != "CTL.TEST.A.001" {
		t.Errorf("resolved finding: got %s, want CTL.TEST.A.001", comparison.Resolved[0].ControlID)
	}
}

func TestCIDiff_EmptyFindings(t *testing.T) {
	dir := t.TempDir()

	baselinePath := writeEvalJSON(t, dir, "baseline.json", nil)
	currentPath := writeEvalJSON(t, dir, "current.json", nil)

	baselineEval, err := artifact.NewLoader().Evaluation(context.Background(), baselinePath)
	if err != nil {
		t.Fatalf("load baseline: %v", err)
	}
	currentEval, err := artifact.NewLoader().Evaluation(context.Background(), currentPath)
	if err != nil {
		t.Fatalf("load current: %v", err)
	}

	baselineEntries := remediation.BaselineEntriesFromFindings(baselineEval.Findings)
	currentEntries := remediation.BaselineEntriesFromFindings(currentEval.Findings)
	comparison := evaluation.CompareBaseline(baselineEntries, currentEntries)

	if len(comparison.New) != 0 {
		t.Errorf("expected 0 new findings, got %d", len(comparison.New))
	}
	if len(comparison.Resolved) != 0 {
		t.Errorf("expected 0 resolved findings, got %d", len(comparison.Resolved))
	}
}

func TestCIDiff_AllNew(t *testing.T) {
	dir := t.TempDir()

	baselinePath := writeEvalJSON(t, dir, "baseline.json", nil)
	currentPath := writeEvalJSON(t, dir, "current.json", []remediation.Finding{
		{Finding: evaluation.Finding{ControlID: "CTL.TEST.A.001", ControlName: "A", AssetID: "res-1", AssetType: "bucket"}},
	})

	baselineEval, err := artifact.NewLoader().Evaluation(context.Background(), baselinePath)
	if err != nil {
		t.Fatalf("load baseline: %v", err)
	}
	currentEval, err := artifact.NewLoader().Evaluation(context.Background(), currentPath)
	if err != nil {
		t.Fatalf("load current: %v", err)
	}

	baselineEntries := remediation.BaselineEntriesFromFindings(baselineEval.Findings)
	currentEntries := remediation.BaselineEntriesFromFindings(currentEval.Findings)
	comparison := evaluation.CompareBaseline(baselineEntries, currentEntries)

	if len(comparison.New) != 1 {
		t.Fatalf("expected 1 new finding, got %d", len(comparison.New))
	}
	if len(comparison.Resolved) != 0 {
		t.Errorf("expected 0 resolved findings, got %d", len(comparison.Resolved))
	}
}

func TestCIDiff_AllResolved(t *testing.T) {
	dir := t.TempDir()

	baselinePath := writeEvalJSON(t, dir, "baseline.json", []remediation.Finding{
		{Finding: evaluation.Finding{ControlID: "CTL.TEST.A.001", ControlName: "A", AssetID: "res-1", AssetType: "bucket"}},
	})
	currentPath := writeEvalJSON(t, dir, "current.json", nil)

	baselineEval, err := artifact.NewLoader().Evaluation(context.Background(), baselinePath)
	if err != nil {
		t.Fatalf("load baseline: %v", err)
	}
	currentEval, err := artifact.NewLoader().Evaluation(context.Background(), currentPath)
	if err != nil {
		t.Fatalf("load current: %v", err)
	}

	baselineEntries := remediation.BaselineEntriesFromFindings(baselineEval.Findings)
	currentEntries := remediation.BaselineEntriesFromFindings(currentEval.Findings)
	comparison := evaluation.CompareBaseline(baselineEntries, currentEntries)

	if len(comparison.New) != 0 {
		t.Errorf("expected 0 new findings, got %d", len(comparison.New))
	}
	if len(comparison.Resolved) != 1 {
		t.Fatalf("expected 1 resolved finding, got %d", len(comparison.Resolved))
	}
}
