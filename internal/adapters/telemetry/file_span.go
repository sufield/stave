package telemetry

import (
	"slices"
	"time"

	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/core/trace"
)

// fileSpan records the decision steps for a single control×asset evaluation.
// NOT safe for concurrent use — each span is owned by one goroutine.
type fileSpan struct {
	tracer     *LocalFileTracer
	resourceID string
	policyID   string
	start      time.Time
	steps      []trace.Step
	verdict    string
	confidence string
	findingID  string
}

func (s *fileSpan) RecordStep(name string, input, result any) {
	s.steps = append(s.steps, trace.Step{
		Name:   name,
		Input:  input,
		Result: result,
	})
}

func (s *fileSpan) SetVerdict(verdict, confidence string) {
	s.verdict = verdict
	s.confidence = confidence
}

func (s *fileSpan) SetFindingID(id string) {
	s.findingID = id
}

// isRecording reports whether the span is attached to an active
// tracer and should therefore record telemetry data on End.
// Encapsulates the nil-tracer probe so the lifecycle state of the
// span ("recording vs detached") reads as the question End is
// asking, not as a memory-safety check.
func (s *fileSpan) isRecording() bool {
	return s != nil && s.tracer != nil
}

func (s *fileSpan) End() {
	// A detached span (constructed directly without going through
	// LocalFileTracer.BeginAssessment) should swallow steps silently
	// rather than panic on the tracer.append dereference.
	if !s.isRecording() {
		return
	}
	// Clone steps before handing it to the tracer. The fileSpan
	// owner could (incorrectly) call RecordStep after End and grow
	// s.steps, which would mutate the slice the tracer kept a
	// reference to — a silent corruption of the recorded trace
	// for the previous assessment. Cloning here makes End the
	// effective hand-off point; any mutation after this is
	// confined to the caller's view.
	s.tracer.append(trace.Assessment{
		ResourceID: s.resourceID,
		PolicyID:   s.policyID,
		Verdict:    trace.Verdict(s.verdict),
		Confidence: s.confidence,
		Steps:      slices.Clone(s.steps),
		FindingID:  s.findingID,
	})
}

// Compile-time check.
var _ ports.AssessmentSpan = (*fileSpan)(nil)
