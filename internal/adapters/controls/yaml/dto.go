package yaml

import (
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
)

// yamlControlDefinition is the YAML wire-format representation of a control definition.
// It mirrors policy.ControlDefinition with YAML struct tags, keeping the domain layer
// free of serialization concerns.
type yamlControlDefinition struct {
	DSLVersion           string               `yaml:"dsl_version"`
	ID                   kernel.ControlID     `yaml:"id"`
	Name                 string               `yaml:"name"`
	Description          string               `yaml:"description"`
	Severity             policy.Severity      `yaml:"severity,omitempty"`
	Domain               kernel.AssetDomain   `yaml:"domain,omitempty"`
	ScopeTags            []string             `yaml:"scope_tags,omitempty"`
	ApplicableAssetTypes []string             `yaml:"applicable_asset_types,omitempty"`
	Compliance           map[string]any       `yaml:"compliance,omitempty"`
	Type                 policy.ControlType   `yaml:"type"`
	Classification       string               `yaml:"classification"`
	Params               map[string]any       `yaml:"params"`
	UnsafePredicate      yamlUnsafePredicate  `yaml:"unsafe_predicate"`
	UnsafePredicateAlias string               `yaml:"unsafe_predicate_alias,omitempty"`
	Remediation          *yamlRemediationSpec `yaml:"remediation,omitempty"`
	Exposure             *yamlExposure        `yaml:"exposure,omitempty"`
	ObservationFields    []string             `yaml:"observation_fields,omitempty"`
	Alternatives         []yamlAlternative    `yaml:"alternatives,omitempty"`
	MitreAttack          []yamlMitreAttack    `yaml:"mitre_attack,omitempty"`
	ValidatedAgainst     []yamlLabValidation  `yaml:"validated_against,omitempty"`
	Tests                []policy.ControlTest `yaml:"tests,omitempty"`

	Taxonomy            []kernel.CategoryID `yaml:"taxonomy,omitempty"`
	SubtractiveCategory []string            `yaml:"subtractive_category,omitempty"`

	PayerExempt              *bool   `yaml:"payer_exempt,omitempty"`
	PayerCompensatingControl *string `yaml:"payer_compensating_control,omitempty"`

	// Defect / Infection / Failure carry the authored triage
	// chain from Andreas Zeller's Why Programs Fail, applied to
	// cloud misconfigurations. All three are optional during
	// catalog authoring; absent fields produce empty strings and
	// rendering skips the corresponding output sections.
	Defect    string `yaml:"defect,omitempty"`
	Infection string `yaml:"infection,omitempty"`
	Failure   string `yaml:"failure,omitempty"`

	// Archetype is the structural defect classification (e.g.
	// "ghost-reference"). Optional; controls without an archetype are
	// excluded from `stave expand` results. See internal/archetype.
	Archetype string `yaml:"archetype,omitempty"`

	// Scope is "atomic" (single-asset predicate) or "compound"
	// (multi-asset predicate). Orthogonal to Classification.
	// Populated by the build-time scope classifier when not set
	// explicitly. See internal/tools/scope-classifier.
	Scope string `yaml:"scope,omitempty"`

	// CorpusReference cites the real-world attack pattern (MITRE
	// technique, incident, Stratus Red Team scenario, etc.).
	// Required when Scope == "compound" — enforced by build-time
	// validator.
	CorpusReference string `yaml:"corpus_reference,omitempty"`

	// IntentRationale is the WHY-prose flowing into ControlFact.
	// See policy.ControlDefinition.IntentRationale for full semantics.
	IntentRationale string `yaml:"intent_rationale,omitempty"`

	// ForbiddenState is the high-level invariant predicate. Reuses
	// the same wire shape as UnsafePredicate so authors can express
	// invariants with the same any/all + rule vocabulary.
	ForbiddenState yamlUnsafePredicate `yaml:"forbidden_state,omitempty"`

	// VerdictOnError controls fallback behavior when the predicate
	// evaluator is unavailable: safe, fail_closed, or empty (inconclusive).
	VerdictOnError string `yaml:"verdict_on_error,omitempty"`
}

// yamlAlternative is the YAML wire-format for policy.Alternative.
type yamlAlternative struct {
	Tool     string `yaml:"tool"`
	CheckID  string `yaml:"check_id"`
	Coverage string `yaml:"coverage"`
	Note     string `yaml:"note,omitempty"`
}

// yamlUnsafePredicate is the YAML wire-format for policy.UnsafePredicate.
type yamlUnsafePredicate struct {
	Any []yamlPredicateRule `yaml:"any,omitempty"`
	All []yamlPredicateRule `yaml:"all,omitempty"`
}

// yamlPredicateRule is the YAML wire-format for policy.PredicateRule.
type yamlPredicateRule struct {
	Field          string             `yaml:"field,omitempty"`
	Op             predicate.Operator `yaml:"op,omitempty"`
	Value          any                `yaml:"value,omitempty"`
	ValueFromParam string             `yaml:"value_from_param,omitempty"`

	Any []yamlPredicateRule `yaml:"any,omitempty"`
	All []yamlPredicateRule `yaml:"all,omitempty"`
}

// yamlRemediationSpec is the YAML wire-format for policy.RemediationSpec.
type yamlRemediationSpec struct {
	Description string `yaml:"description"`
	Action      string `yaml:"action"`
	Example     string `yaml:"example,omitempty"`
}

// yamlExposure is the YAML wire-format for policy.Exposure.
type yamlExposure struct {
	Type           string `yaml:"type"`
	PrincipalScope string `yaml:"principal_scope"`
}

type yamlMitreAttack struct {
	ID     string `yaml:"id"`
	Name   string `yaml:"name"`
	Tactic string `yaml:"tactic"`
}

type yamlLabValidation struct {
	Vendor   string `yaml:"vendor"`
	Lab      string `yaml:"lab"`
	Result   string `yaml:"result"`
	Verified string `yaml:"verified"`
}
