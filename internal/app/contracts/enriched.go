package contracts

import (
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
)

// EnrichedFinding pairs a raw evaluation finding with its remediation guidance.
// This is the port-boundary type used in EnrichedResult. It mirrors the
// fields of remediation.Finding without importing that core package, keeping
// the contracts layer free of business-logic dependencies.
type EnrichedFinding struct {
	evaluation.Finding
	RemediationSpec policy.RemediationSpec      `json:"remediation"`
	RemediationPlan *evaluation.RemediationPlan `json:"fix_plan,omitempty"`
}
