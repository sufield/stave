package remediation

import (
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
)

// FindingEnricher enriches raw evaluation findings with remediation guidance.
type FindingEnricher interface {
	EnrichFindings(evaluation.Audit) []Finding
}

// Finding pairs a raw violation with its associated remediation guidance.
type Finding struct {
	evaluation.Finding
	RemediationSpec policy.RemediationSpec      `json:"remediation"`
	RemediationPlan *evaluation.RemediationPlan `json:"fix_plan,omitempty"`
}

// resolveSpec returns remediation guidance for a finding.
// Prioritizes YAML-defined remediation from control metadata,
// falling back to class-based defaults from the control definition layer.
func resolveSpec(f evaluation.Finding) policy.RemediationSpec {
	if f.ControlRemediation != nil {
		return *f.ControlRemediation
	}
	return policy.DefaultRemediationForClass(f.ControlID.Classify())
}
