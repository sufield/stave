package remediation

import (
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
)

// FindingEnricher enriches raw evaluation findings with remediation guidance.
type FindingEnricher interface {
	EnrichFindings(*evaluation.ComplianceReport) []Finding
}

// Finding pairs a raw violation with its associated remediation guidance.
type Finding struct {
	evaluation.Finding
	RemediationSpec policy.RemediationSpec      `json:"remediation"`
	RemediationPlan *evaluation.RemediationPlan `json:"fix_plan,omitempty"`
}

// HasRemediationAction reports whether the finding carries a
// populated remediation action — the catalog author wrote a fix
// instruction for this control. Distinct from "has a remediation
// block": a stub block with no Action string is not actionable.
// Centralised here so consumers (priority ranking, plan grouping)
// stop open-coding the RemediationSpec.Action != "" check.
func (f *Finding) HasRemediationAction() bool {
	return f != nil && f.RemediationSpec.HasAction()
}

// HasRemediationContext reports whether the finding carries
// enough material to populate a RemediationContext block: either
// a non-empty reasoning trace (the predicate clauses that fired)
// or a non-empty remediation spec (Action or Description). The
// DTO mapper used to ask both probes inline; centralising the
// "should we emit a context?" question on the type keeps the
// shape decision in one place.
func (f *Finding) HasRemediationContext() bool {
	if f == nil {
		return false
	}
	if f.HasReasoningTrace() {
		return true
	}
	return !f.RemediationSpec.IsEmpty()
}

// HasRemediationCommand reports whether the finding's plan
// carries an executable command. The plan pointer is nil when no
// remediation enricher ran; the Command field is empty for
// advisory plans. Both branches collapse to a single predicate
// callers consume.
func (f *Finding) HasRemediationCommand() bool {
	return f != nil && f.RemediationPlan != nil && f.RemediationPlan.Command != ""
}

// RemediationCommand returns the plan's Command together with a
// presence flag. Replaces the (RemediationPlan != nil &&
// RemediationPlan.Command != "") probe + dereference at the
// mapper site.
func (f *Finding) RemediationCommand() (string, bool) {
	if !f.HasRemediationCommand() {
		return "", false
	}
	return f.RemediationPlan.Command, true
}

// resolveSpec returns remediation guidance for a finding.
// Prioritizes YAML-defined remediation from control metadata,
// falling back to class-based defaults from the control definition layer.
func resolveSpec(f *evaluation.Finding) policy.RemediationSpec {
	if f.ControlRemediation != nil {
		return *f.ControlRemediation
	}
	return policy.DefaultRemediationForClass(f.ControlID.Classify())
}
