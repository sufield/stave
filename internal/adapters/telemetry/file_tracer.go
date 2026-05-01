// Package telemetry provides observability adapters for the evaluation engine.
// The LocalFileTracer writes a structured audit trail (audit_trace.json) that
// records every decision the engine made, enabling security researchers to
// verify the reasoning chain for both PASS and VIOLATION verdicts.
//
// Air-gap safe: no network calls, no OpenTelemetry dependency.
package telemetry

import (
	"sync"
	"time"

	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/core/trace"
)

// LocalFileTracer accumulates assessment spans in memory during an evaluation
// run, then produces a LogicTrace for file export. Thread-safe — multiple
// goroutines may call BeginAssessment concurrently.
type LocalFileTracer struct {
	mu          sync.Mutex
	assessments []trace.Assessment
}

// NewLocalFileTracer creates a tracer that aggregates assessments in memory.
func NewLocalFileTracer() *LocalFileTracer {
	return &LocalFileTracer{}
}

// BeginAssessment starts recording a control×asset evaluation.
// The returned span is NOT safe for concurrent use — each span is owned
// by a single goroutine for its lifetime.
func (t *LocalFileTracer) BeginAssessment(resourceID, policyID string) ports.AssessmentSpan {
	return &fileSpan{
		tracer:     t,
		resourceID: resourceID,
		policyID:   policyID,
		start:      time.Now(),
	}
}

// Finalize assembles the accumulated trace data into a LogicTrace.
func (t *LocalFileTracer) Finalize(args ports.FinalizeArgs) *trace.LogicTrace {
	t.mu.Lock()
	defer t.mu.Unlock()

	return &trace.LogicTrace{
		SchemaVersion: trace.SchemaVersion,
		RunID:         args.RunID,
		GeneratedAt:   time.Now().UTC(),
		StaveVersion:  args.StaveVersion,
		InputHashes:   args.Hashes,
		Assessments:   t.assessments,
		Summary:       trace.ComputeSummary(t.assessments),
	}
}

// append adds a completed assessment to the tracer. Called by fileSpan.End().
func (t *LocalFileTracer) append(a trace.Assessment) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.assessments = append(t.assessments, a)
}

// Compile-time check.
var _ ports.Tracer = (*LocalFileTracer)(nil)
