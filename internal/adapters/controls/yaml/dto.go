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
	Tests                []policy.ControlTest `yaml:"tests,omitempty"`

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

	// IntentRationale is the WHY-prose flowing into ControlFact.
	// See policy.ControlDefinition.IntentRationale for full semantics.
	IntentRationale string `yaml:"intent_rationale,omitempty"`

	// ForbiddenState is the high-level invariant predicate. Reuses
	// the same wire shape as UnsafePredicate so authors can express
	// invariants with the same any/all + rule vocabulary.
	ForbiddenState yamlUnsafePredicate `yaml:"forbidden_state,omitempty"`
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
