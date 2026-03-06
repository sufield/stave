package remediation

import (
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
)

// FindingEnricher enriches raw evaluation findings with remediation guidance.
type FindingEnricher interface {
	EnrichFindings(evaluation.Result) []Finding
}

var _ FindingEnricher = (*Mapper)(nil)

// Mapper maps violations to remediation guidance.
// Mapping is deterministic, based on control ID patterns.
type Mapper struct {
	planner Planner
}

// NewMapper creates a new remediation mapper.
func NewMapper() *Mapper {
	return &Mapper{planner: NewPlanner()}
}

// MapFinding returns remediation guidance for a violation.
// Prefers YAML-defined remediation from the control, falls back to prefix patterns.
func (m *Mapper) MapFinding(f evaluation.Finding) policy.RemediationSpec {
	if f.ControlRemediation != nil {
		return *f.ControlRemediation
	}

	switch f.ControlID.Classify() {
	case kernel.ClassS3Public:
		return policy.RemediationSpec{
			Description: "Resource is publicly exposed beyond threshold.",
			Action:      "Remove public access, confirm via new snapshot.",
		}
	case kernel.ClassS3General:
		return policy.RemediationSpec{
			Description: "Resource has unsafe state configuration.",
			Action:      "Review and correct the state configuration, verify in new snapshot.",
		}
	default:
		return policy.RemediationSpec{
			Description: "Control violation detected.",
			Action:      "Review the unsafe configuration and remediate.",
		}
	}
}

// MapFindings returns remediation specs for all violations in a result.
func (m *Mapper) MapFindings(result evaluation.Result) []policy.RemediationSpec {
	remediationSpecs := make([]policy.RemediationSpec, len(result.Findings))
	for i, f := range result.Findings {
		remediationSpecs[i] = m.MapFinding(f)
	}
	return remediationSpecs
}

// Finding pairs a violation with remediation guidance for output.
type Finding struct {
	evaluation.Finding
	RemediationSpec policy.RemediationSpec      `json:"remediation"`
	RemediationPlan *evaluation.RemediationPlan `json:"fix_plan,omitempty"`
}

// Sanitized returns a deep copy with infrastructure identifiers replaced by
// deterministic tokens. Delegates to the kernel.Sanitizer for primitives.
func (f Finding) Sanitized(r kernel.Sanitizer) Finding {
	out := f
	out.AssetID = asset.ID(r.ID(string(f.AssetID)))

	if f.Source != nil {
		src := *f.Source
		src.File = r.Path(src.File)
		out.Source = &src
	}

	if len(f.Evidence.Misconfigurations) > 0 {
		misconfigs := make([]policy.Misconfiguration, len(f.Evidence.Misconfigurations))
		for i, m := range f.Evidence.Misconfigurations {
			misconfigs[i] = m.Sanitized()
		}
		out.Evidence.Misconfigurations = misconfigs
	}

	if f.Evidence.SourceEvidence != nil {
		se := *f.Evidence.SourceEvidence
		se.PolicyPublicStatements = redactStrings(se.PolicyPublicStatements, r)
		se.ACLPublicGrantees = redactStrings(se.ACLPublicGrantees, r)
		out.Evidence.SourceEvidence = &se
	}

	if f.RemediationPlan != nil {
		plan := *f.RemediationPlan
		plan.Target.AssetID = asset.ID(r.ID(string(plan.Target.AssetID)))
		out.RemediationPlan = &plan
	}

	return out
}

// redactStrings replaces every element with "[SANITIZED]".
func redactStrings(lines []string, r kernel.Sanitizer) []string {
	if len(lines) == 0 {
		return lines
	}
	out := make([]string, len(lines))
	for i := range lines {
		out[i] = r.Value(lines[i])
	}
	return out
}

// EnrichFindings combines violations with their remediation guidance.
func (m *Mapper) EnrichFindings(result evaluation.Result) []Finding {
	enriched := make([]Finding, len(result.Findings))
	for i, f := range result.Findings {
		enriched[i] = Finding{
			Finding:         f,
			RemediationSpec: m.MapFinding(f),
		}
		enriched[i].RemediationPlan = m.planner.PlanFor(enriched[i])
	}
	return enriched
}
