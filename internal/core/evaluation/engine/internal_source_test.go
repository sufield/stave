package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/sufield/stave/internal/core/evaluation"
)

// TestInternalFindingSource_NilAssessorErrors pins the
// nil-receiver / nil-assessor contract: a source built without
// an assessor returns errAssessorRequired rather than panicking
// inside Assess.
func TestInternalFindingSource_NilAssessorErrors(t *testing.T) {
	src := NewInternalFindingSource(nil)
	out, err := src.ProduceFindings(context.Background(), evaluation.FindingRequest{})
	if err == nil {
		t.Fatalf("expected error for nil assessor, got nil")
	}
	if !errors.Is(err, errAssessorRequired) {
		t.Errorf("expected errAssessorRequired sentinel, got %v", err)
	}
	if out != nil {
		t.Errorf("expected nil findings on error, got %d", len(out))
	}
}

// TestInternalFindingSource_SatisfiesInterface compile-time
// assertion that the wrapper implements evaluation.FindingSource.
// The check itself happens at compile time via the var _
// declaration in internal_source.go; the test exists so the
// signature drift is also visible in test reports.
func TestInternalFindingSource_SatisfiesInterface(t *testing.T) {
	var _ evaluation.FindingSource = (*InternalFindingSource)(nil)
	var _ evaluation.FindingSource = NewInternalFindingSource(nil)
}
