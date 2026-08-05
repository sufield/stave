package remediation

import (
	"encoding/json"
	"fmt"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
)

// FindingEnricher enriches raw evaluation findings with remediation guidance.
//
// EnrichFindings handles the violation pipeline (report.Findings).
// EnrichMarkerFindings handles fact-recording marker findings
// (report.MarkerFindings). Markers usually carry no remediation —
// they record a fact, not a fix — but the contract surfaces the
// hook so a marker that DOES author a suppression flow gets it.
type FindingEnricher interface {
	EnrichFindings(*evaluation.ComplianceReport) []Finding
	EnrichIndeterminateFindings(*evaluation.ComplianceReport) []Finding
	EnrichMarkerFindings(*evaluation.ComplianceReport) []Finding
}

// Finding pairs a raw violation with its associated remediation guidance.
type Finding struct {
	evaluation.Finding
	RemediationSpec policy.RemediationSpec      `json:"remediation"`
	RemediationPlan *evaluation.RemediationPlan `json:"fix_plan,omitempty"`
}

// MarshalJSON renders this finding by composing the embedded
// evaluation.Finding's wire shape (which carries the private SLA
// fields via its own MarshalJSON shadow) with the
// remediation-and-plan fields the embedded type does not own.
//
// The composition is necessary because Go's JSON encoder
// promotes the embedded type's MarshalJSON method to the outer
// type. Without this method, the encoder would call only the
// inner shadow and silently drop "remediation" and "fix_plan"
// from the wire format.
//
// Implementation strategy: marshal the embedded Finding to an
// object map, splice in the remediation-side fields, re-marshal.
// JSON object key order is unspecified, so this preserves the
// schema-required fields without depending on Go struct order.
func (f *Finding) MarshalJSON() ([]byte, error) {
	if f == nil {
		return []byte("null"), nil
	}
	inner, err := json.Marshal(&f.Finding)
	if err != nil {
		return nil, fmt.Errorf("marshal embedded finding: %w", err)
	}
	var raw map[string]json.RawMessage
	if err = json.Unmarshal(inner, &raw); err != nil {
		return nil, fmt.Errorf("decode embedded finding: %w", err)
	}
	remRaw, err := json.Marshal(f.RemediationSpec)
	if err != nil {
		return nil, fmt.Errorf("marshal remediation: %w", err)
	}
	raw["remediation"] = remRaw
	if f.RemediationPlan != nil {
		planRaw, err := json.Marshal(f.RemediationPlan)
		if err != nil {
			return nil, fmt.Errorf("marshal fix_plan: %w", err)
		}
		raw["fix_plan"] = planRaw
	}
	return json.Marshal(raw)
}

// UnmarshalJSON pairs with MarshalJSON so loaders that read the
// composed wire format reconstruct a remediation.Finding with
// every layer's state intact.
func (f *Finding) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &f.Finding); err != nil {
		return fmt.Errorf("decode embedded finding: %w", err)
	}
	var outer struct {
		RemediationSpec policy.RemediationSpec      `json:"remediation"`
		RemediationPlan *evaluation.RemediationPlan `json:"fix_plan,omitempty"`
	}
	if err := json.Unmarshal(data, &outer); err != nil {
		return fmt.Errorf("decode remediation fields: %w", err)
	}
	f.RemediationSpec = outer.RemediationSpec
	f.RemediationPlan = outer.RemediationPlan
	return nil
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

// HasRemediationPlan reports whether the finding carries a
// remediation plan (the asset-parameterized fix). Replaces the
// bare (f.RemediationPlan != nil) probe in DTO and graph
// emitters.
func (f *Finding) HasRemediationPlan() bool {
	return f != nil && f.RemediationPlan != nil
}

// HasRemediationCommand reports whether the finding's plan
// carries an executable command. The plan pointer is nil when no
// remediation enricher ran; the Command field is empty for
// advisory plans. Both branches collapse to a single predicate
// callers consume.
func (f *Finding) HasRemediationCommand() bool {
	return f.HasRemediationPlan() && f.RemediationPlan.Command != ""
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

// EffectiveRemediationCommand returns the asset-parameterized
// fix string the renderer should display: the plan's Command
// when present (templated against the actual asset), falling
// back to the spec's raw Action template when no plan was
// produced. Empty string when neither path is populated.
//
// Centralises the SARIF / text-detail / fix-plan fallback chain
// so renderers stop branching on (Plan != nil && Command != "")
// at every site.
func (f *Finding) EffectiveRemediationCommand() string {
	if cmd, ok := f.RemediationCommand(); ok {
		return cmd
	}
	if f == nil {
		return ""
	}
	return f.RemediationSpec.Action
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
