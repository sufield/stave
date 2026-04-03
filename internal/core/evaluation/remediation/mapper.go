package remediation

import (
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

// FindingEnricher enriches raw evaluation findings with remediation guidance.
type FindingEnricher interface {
	EnrichFindings(evaluation.Result) []Finding
}

// Ensure Mapper implements FindingEnricher.
var _ FindingEnricher = (*Mapper)(nil)

// Mapper maps violations to remediation guidance based on control ID patterns.
type Mapper struct {
	planner *Planner
}

// NewMapper creates a new remediation mapper with a default planner.
func NewMapper() *Mapper {
	return &Mapper{
		planner: NewPlanner(),
	}
}

// MapFinding returns remediation guidance for a specific violation.
// It prioritizes YAML-defined remediation from the control metadata, falling back to
// class-based defaults if not provided.
func (m *Mapper) MapFinding(f evaluation.Finding) policy.RemediationSpec {
	if f.ControlRemediation != nil {
		return *f.ControlRemediation
	}

	switch f.ControlID.Classify() {
	case kernel.ClassPublicExposure:
		return policy.RemediationSpec{
			Description: "Resource is exposed to the public internet.",
			Action:      "Restrict access to authorized principals only.",
		}
	case kernel.ClassEncryptionMissing:
		return policy.RemediationSpec{
			Description: "Resource data is not encrypted at rest.",
			Action:      "Enable server-side encryption using a managed key.",
		}
	case kernel.ClassBaselineViolation:
		return policy.RemediationSpec{
			Description: "Resource configuration deviates from security baseline.",
			Action:      "Review the misconfigured properties and revert to compliant values.",
		}
	default:
		return policy.RemediationSpec{
			Description: "Security control violation detected.",
			Action:      "Review the finding evidence and remediate the configuration.",
		}
	}
}

// MapFindings returns a slice of remediation specs for all violations in a result.
func (m *Mapper) MapFindings(result evaluation.Result) []policy.RemediationSpec {
	specs := make([]policy.RemediationSpec, len(result.Findings))
	for i, f := range result.Findings {
		specs[i] = m.MapFinding(f)
	}
	return specs
}

// Finding pairs a raw violation with its associated remediation guidance.
type Finding struct {
	evaluation.Finding
	RemediationSpec policy.RemediationSpec      `json:"remediation"`
	RemediationPlan *evaluation.RemediationPlan `json:"fix_plan,omitempty"`
}

// Sanitized returns a deep copy of the Finding with infrastructure identifiers
// masked by deterministic tokens.
func (f Finding) Sanitized(s kernel.Sanitizer) Finding {
	// f is a value copy, but we must deep-copy pointers and slices.
	out := f
	out.AssetID = asset.ID(s.ID(string(f.AssetID)))

	if f.Source != nil {
		src := *f.Source
		src.File = s.Path(src.File)
		out.Source = &src
	}

	if len(f.Evidence.Misconfigurations) > 0 {
		out.Evidence.Misconfigurations = make([]policy.Misconfiguration, len(f.Evidence.Misconfigurations))
		for i, m := range f.Evidence.Misconfigurations {
			out.Evidence.Misconfigurations[i] = m.Sanitized()
		}
	}

	if f.Evidence.SourceEvidence != nil {
		se := *f.Evidence.SourceEvidence
		se.IdentityStatements = sanitizeSlice(se.IdentityStatements, s)
		se.ResourceGrantees = sanitizeSlice(se.ResourceGrantees, s)
		out.Evidence.SourceEvidence = &se
	}

	if f.RemediationPlan != nil {
		plan := *f.RemediationPlan
		plan.Target.AssetID = asset.ID(s.ID(string(plan.Target.AssetID)))
		out.RemediationPlan = &plan
	}

	return out
}

// EnrichFindings combines raw violations with their mapping and remediation plans.
func (m *Mapper) EnrichFindings(result evaluation.Result) []Finding {
	enriched := make([]Finding, len(result.Findings))
	for i, f := range result.Findings {
		item := Finding{
			Finding:         f,
			RemediationSpec: m.MapFinding(f),
		}
		// Generate the specific action plan (Fix Plan) for this finding.
		item.RemediationPlan = m.planner.PlanFor(item)
		enriched[i] = item
	}
	return enriched
}

// sanitizeSlice clones and replaces every element using the provided sanitizer.
func sanitizeSlice[T ~string](items []T, s kernel.Sanitizer) []T {
	if len(items) == 0 {
		return nil
	}
	out := make([]T, len(items))
	for i := range items {
		out[i] = T(s.Value(string(items[i])))
	}
	return out
}
