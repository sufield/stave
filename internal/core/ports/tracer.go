package ports

import "github.com/sufield/stave/internal/core/trace"

// Tracer records the reasoning chain during security evaluation.
// Implementations must be safe for concurrent use — BeginAssessment
// may be called from multiple goroutines if the engine is parallelized.
type Tracer interface {
	// BeginAssessment starts recording a control×asset evaluation span.
	// The returned AssessmentSpan is NOT safe for concurrent use — each
	// span is owned by a single goroutine for its lifetime.
	BeginAssessment(resourceID, policyID string) AssessmentSpan

	// Finalize assembles the accumulated trace data into a LogicTrace.
	// Called once after all assessments are complete.
	Finalize(runID, staveVersion string, hashes map[string]string) *trace.LogicTrace
}

// AssessmentSpan records steps within a single control×asset evaluation.
// A span is created by Tracer.BeginAssessment and must be closed with End().
// Spans are NOT safe for concurrent use.
type AssessmentSpan interface {
	// RecordStep logs a decision point with what the engine examined (input)
	// and what it concluded (result).
	RecordStep(name string, input, result any)

	// SetVerdict records the final outcome of this assessment.
	SetVerdict(verdict, confidence string)

	// SetFindingID links this assessment to a finding in the ComplianceReport.
	SetFindingID(id string)

	// End completes the span and commits it to the parent Tracer.
	End()
}
