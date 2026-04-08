package telemetry

import (
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

func (s *fileSpan) End() {
	s.tracer.append(trace.Assessment{
		ResourceID: s.resourceID,
		PolicyID:   s.policyID,
		Verdict:    s.verdict,
		Confidence: s.confidence,
		Steps:      s.steps,
		FindingID:  s.findingID,
	})
}

// Compile-time check.
var _ ports.AssessmentSpan = (*fileSpan)(nil)
