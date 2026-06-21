// Package fix provides the single-finding remediation and fix-loop
// verification workflows. Command handlers in cmd/ delegate to this package.
package fix

import (
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
)

// FindingsParser parses raw evaluation JSON into findings.
// Injected from the adapters layer by cmd/ callers.
type FindingsParser func(data []byte) ([]remediation.Finding, error)

// Service orchestrates finding remediation workflows.
type Service struct {
	Clock         ports.Clock
	Planner       *remediation.Planner
	Sanitizer     kernel.Sanitizer
	ParseFindings FindingsParser
	CELEvaluator  policy.PredicateEval
	ReadFile      func(string) ([]byte, error) // injected by cmd layer; must enforce size limits
}

// NewService creates a Service. The caller must set ParseFindings
// before calling Loop.
func NewService(clock ports.Clock, planner *remediation.Planner) *Service {
	return &Service{
		Clock:   clock,
		Planner: planner,
	}
}

// EnsurePlan mutates f in place to ensure it has a non-nil
// RemediationPlan, generating one via the default planner when
// missing. Centralises the "every finding needs a plan" business
// rule. Pointer receiver because remediation.Finding is a heavy
// value type and gocritic flags the by-value form (864 bytes).
func EnsurePlan(f *remediation.Finding) {
	if f == nil {
		return
	}
	if f.RemediationPlan == nil {
		f.RemediationPlan = remediation.NewPlanner().PlanFor(f)
	}
}
