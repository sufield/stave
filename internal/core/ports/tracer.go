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
	//
	// The named-field FinalizeArgs prevents callers from accidentally
	// swapping RunID and StaveVersion — both are short strings, both
	// look interchangeable, and the previous (runID, staveVersion
	// string, ...) tuple shape made the swap silently compile.
	Finalize(args FinalizeArgs) *trace.LogicTrace
}

// FinalizeArgs carries the parameters to Tracer.Finalize. Named so
// the run identity and the build version cannot be transposed at
// the call site.
type FinalizeArgs struct {
	RunID        string
	StaveVersion string
	Hashes       map[string]string
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
