package engine

import "github.com/sufield/stave/internal/core/ports"

// nopSpan is a zero-allocation, no-op implementation of ports.AssessmentSpan.
// Used when the Assessor has no Tracer configured — avoids nil checks at
// every instrumentation point.
type nopSpan struct{}

func (nopSpan) RecordStep(string, any, any) {}
func (nopSpan) SetVerdict(string, string)   {}
func (nopSpan) SetFindingID(string)         {}
func (nopSpan) End()                        {}

// Compile-time check.
var _ ports.AssessmentSpan = nopSpan{}
