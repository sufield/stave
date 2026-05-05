package shadow

import (
	"context"

	"github.com/sufield/stave/internal/core/evaluation"
)

// PrecomputedFindingSource exposes a pre-computed slice of
// findings as a FindingSource. The shadow wiring uses it as
// the PRIMARY of a ShadowFindingSource decorator so the
// dark-launch comparison can run after the assessor has
// already produced its findings — re-invoking the assessor
// just for divergence logging would double the cost of every
// shadowed apply call.
//
// Iter 2.4 introduced this type alongside the now-retired
// StubFindingSource. 3.1.4 removed StubFindingSource (the real
// PythonSolverSource is the secondary now); PrecomputedFindingSource
// remains because it serves the unrelated "wrap a known
// findings slice as a source" use case.
type PrecomputedFindingSource struct {
	findings []evaluation.Finding
}

// NewPrecomputedFindingSource wraps an already-computed findings
// slice as a FindingSource. The slice is held by reference;
// callers must not mutate it after passing it in.
func NewPrecomputedFindingSource(findings []evaluation.Finding) *PrecomputedFindingSource {
	return &PrecomputedFindingSource{findings: findings}
}

// ProduceFindings returns the held slice unchanged.
func (s *PrecomputedFindingSource) ProduceFindings(_ context.Context, _ evaluation.FindingRequest) ([]evaluation.Finding, error) {
	return s.findings, nil
}

// Compile-time assertion.
var _ evaluation.FindingSource = (*PrecomputedFindingSource)(nil)
