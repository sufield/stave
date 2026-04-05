package evaluation

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/safetyenvelope"
)

func TestLoader_LoadFromFile_ValidJSON(t *testing.T) {
	dir := t.TempDir()
	result := evaluation.Audit{
		Run: evaluation.RunInfo{
			StaveVersion:      "test",
			MaxUnsafeDuration: kernel.Duration(24 * time.Hour),
			Snapshots:         2,
		},
		Summary: evaluation.Summary{AssetsEvaluated: 1},
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(dir, "result.json")
	if writeErr := os.WriteFile(path, data, 0o600); writeErr != nil {
		t.Fatalf("write: %v", writeErr)
	}

	loader := &Loader{}
	got, err := loader.LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile() error = %v", err)
	}
	if got.Summary.AssetsEvaluated != 1 {
		t.Errorf("AssetsEvaluated = %d, want 1", got.Summary.AssetsEvaluated)
	}
}

func TestLoader_LoadFromReader_ValidJSON(t *testing.T) {
	result := evaluation.Audit{
		Summary: evaluation.Summary{Violations: 3},
	}
	data, _ := json.Marshal(result)

	loader := &Loader{}
	got, err := loader.LoadFromReader(bytes.NewReader(data), "test")
	if err != nil {
		t.Fatalf("LoadFromReader() error = %v", err)
	}
	if got.Summary.Violations != 3 {
		t.Errorf("Violations = %d, want 3", got.Summary.Violations)
	}
}

func TestLoader_LoadEnvelopeFromFile_ValidEnvelope(t *testing.T) {
	dir := t.TempDir()
	env := safetyenvelope.NewEvaluation(safetyenvelope.EvaluationRequest{
		Run: evaluation.RunInfo{
			StaveVersion:      "test",
			Now:               time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
			MaxUnsafeDuration: kernel.Duration(24 * time.Hour),
			Snapshots:         2,
		},
		Summary:      evaluation.Summary{AssetsEvaluated: 1},
		SafetyStatus: evaluation.StatusSafe,
		Findings:     []remediation.Finding{},
	})
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(dir, "eval.json")
	if writeErr := os.WriteFile(path, data, 0o600); writeErr != nil {
		t.Fatalf("write: %v", writeErr)
	}

	loader := &Loader{}
	got, err := loader.LoadEnvelopeFromFile(context.Background(), path)
	if err != nil {
		t.Fatalf("LoadEnvelopeFromFile() error = %v", err)
	}
	if got.Kind != safetyenvelope.KindEvaluation {
		t.Errorf("Kind = %q, want evaluation", got.Kind)
	}
}

func TestLoader_LoadEnvelopeFromFile_MissingFile(t *testing.T) {
	loader := &Loader{}
	_, err := loader.LoadEnvelopeFromFile(context.Background(), "/nonexistent/path.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoader_LoadEnvelopeFromFile_WrongKind(t *testing.T) {
	dir := t.TempDir()
	env := map[string]any{
		"kind":           "not-evaluation",
		"schema_version": "out.v0.1",
	}
	data, _ := json.Marshal(env)
	path := filepath.Join(dir, "eval.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	loader := &Loader{}
	_, err := loader.LoadEnvelopeFromFile(context.Background(), path)
	if err == nil || !strings.Contains(err.Error(), "invalid artifact kind") {
		t.Fatalf("expected kind mismatch error, got: %v", err)
	}
}

func TestPrepareBaseline_InvalidKind(t *testing.T) {
	base := &evaluation.Baseline{Kind: "wrong"}
	err := PrepareBaseline(base, "evaluation", "test.json")
	if err == nil || !strings.Contains(err.Error(), "invalid baseline kind") {
		t.Fatalf("expected kind error, got: %v", err)
	}
}

func TestPrepareBaseline_InitializesNilFindings(t *testing.T) {
	base := &evaluation.Baseline{Kind: "evaluation"}
	err := PrepareBaseline(base, "evaluation", "test.json")
	if err != nil {
		t.Fatalf("PrepareBaseline() error = %v", err)
	}
	if base.Findings == nil {
		t.Fatal("expected Findings to be initialized")
	}
}

func TestParseFindings_DirectResult(t *testing.T) {
	data := `{"findings":[]}`
	findings, err := ParseFindings([]byte(data))
	if err != nil {
		t.Fatalf("ParseFindings() error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("len(findings) = %d, want 0", len(findings))
	}
}

func TestParseFindings_APIWrapped(t *testing.T) {
	data := `{"ok":true,"data":{"findings":[]}}`
	findings, err := ParseFindings([]byte(data))
	if err != nil {
		t.Fatalf("ParseFindings() error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("len(findings) = %d, want 0", len(findings))
	}
}

func TestParseFindings_NoFindings(t *testing.T) {
	data := `{"some_key":"some_value"}`
	_, err := ParseFindings([]byte(data))
	if err == nil || err != ErrNoFindings {
		t.Fatalf("expected ErrNoFindings, got: %v", err)
	}
}

func TestParseFindings_InvalidJSON(t *testing.T) {
	_, err := ParseFindings([]byte("{bad"))
	if err == nil {
		t.Fatal("expected JSON parse error")
	}
}
