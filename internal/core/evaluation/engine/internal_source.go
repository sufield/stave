package engine

import (
	"context"

	"github.com/sufield/stave/internal/core/evaluation"
)

// InternalFindingSource is the wrapper that exposes the legacy
// CEL/strategy engine through the evaluation.FindingSource
// interface. It is the equivalence oracle for Iter 2.3 (shadow
// decorator) and Iter 4.1 (differential testing): every
// production run today flows through this source, and
// Z3-backed sources are validated against its output.
//
// Iteration 2.2 lands the seam. The judgment logic — lifecycle
// build, strategy dispatch, exemption / exception filtering,
// acknowledgment application — still lives inside Assessor.Assess()
// proper. ProduceFindings invokes Assess and returns the findings
// from the resulting ComplianceReport. A future commit relocates
// the judgment into ProduceFindings directly so Assess() shrinks
// to pre-pass + delegate + compile-report; that move is gated on
// the differential harness landing in 4.1, which catches any
// behavioral drift the relocation introduces.
//
// The wrapper deliberately carries an *Assessor rather than the
// raw dependency list: the Assessor's option machinery
// (WithControls, WithPredicateEval, WithExemptions, ...) is the
// canonical configuration surface, and duplicating it on
// InternalFindingSource would create two parallel construction
// paths that drift over time.
type InternalFindingSource struct {
	assessor *Assessor
}

// NewInternalFindingSource constructs a source backed by the
// supplied Assessor. The Assessor's deps (controls, predicate
// evaluator, parser, exemptions, exceptions, acknowledgments,
// SLA threshold, hasher, clock, tracer, confidence, continuity
// limit) all flow through. The constructor does not validate
// the assessor — callers wire it via the existing NewAssessor +
// option helpers; missing deps surface as the same precondition
// errors Assessor.Assess() emits today.
func NewInternalFindingSource(assessor *Assessor) *InternalFindingSource {
	return &InternalFindingSource{assessor: assessor}
}

// ProduceFindings satisfies evaluation.FindingSource. The req's
// Controls and Snapshots take precedence over the wrapped
// Assessor's preset values: a caller that wants to evaluate a
// different catalog or snapshot set per call wires it via the
// request rather than rebuilding the Assessor.
//
// Now and SLADefault are advisory in this implementation —
// the legacy Assessor reads its own clock and SLA threshold
// from its configured options. A future relocation of judgment
// into ProduceFindings will honor req.Now / req.SLADefault
// directly. The shadow decorator (Iter 2.3) and the differential
// harness (Iter 4.1) will pin the request fields against the
// underlying assessor state to detect drift.
func (s *InternalFindingSource) ProduceFindings(ctx context.Context, req evaluation.FindingRequest) ([]evaluation.Finding, error) {
	if s == nil || s.assessor == nil {
		return nil, errAssessorRequired
	}
	if len(req.Controls) > 0 {
		s.assessor.controls = req.Controls
	}
	report, err := s.assessor.Assess(ctx, req.Snapshots)
	if err != nil {
		return nil, err
	}
	return findingsFromReport(&report), nil
}

// findingsFromReport extracts the findings slice from a
// ComplianceReport. ComplianceReport carries findings under
// the Findings field; centralizing the extraction here means
// a future report-shape change lands once. Pointer receiver
// avoids the 616-byte by-value copy gocritic flagged.
func findingsFromReport(report *evaluation.ComplianceReport) []evaluation.Finding {
	if report == nil {
		return nil
	}
	return report.Findings
}

// errAssessorRequired is returned by ProduceFindings when the
// source was constructed with a nil assessor. Sentinel-typed
// rather than fmt.Errorf'd so tests can errors.Is against it.
var errAssessorRequired = sourceError("internal_source: assessor is required")

type sourceError string

func (e sourceError) Error() string { return string(e) }

// Compile-time assertion that InternalFindingSource satisfies
// the FindingSource contract. Catches signature drift at build
// time rather than at the next caller's runtime.
var _ evaluation.FindingSource = (*InternalFindingSource)(nil)
