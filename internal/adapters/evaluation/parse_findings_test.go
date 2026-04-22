package evaluation

import (
	"testing"

	coreeval "github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestParseFindings_DirectFormat(t *testing.T) {
	raw := []byte(`{"findings": [{"control_id": "CTL.TEST.001", "severity": "high"}]}`)
	findings, err := ParseFindings(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

func TestParseFindings_WrappedEnvelope(t *testing.T) {
	raw := []byte(`{"ok": true, "data": {"findings": [{"control_id": "CTL.A"}]}}`)
	findings, err := ParseFindings(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

func TestParseFindings_EmptyList(t *testing.T) {
	raw := []byte(`{"findings": []}`)
	findings, err := ParseFindings(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestPrepareBaseline_WrongKind(t *testing.T) {
	base := &coreeval.Baseline{Kind: kernel.OutputKind("wrong_kind")}
	err := PrepareBaseline(base, kernel.OutputKind("expected_kind"), "test.json")
	if err == nil {
		t.Fatal("expected error for wrong kind")
	}
}

func TestPrepareBaseline_NilFindings(t *testing.T) {
	base := &coreeval.Baseline{Kind: kernel.OutputKind("evaluation")}
	err := PrepareBaseline(base, kernel.OutputKind("evaluation"), "test.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if base.Findings == nil {
		t.Fatal("nil findings should be initialized to empty slice")
	}
}
