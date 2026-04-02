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
	DSLVersion           string                   `yaml:"dsl_version"`
	ID                   kernel.ControlID         `yaml:"id"`
	Name                 string                   `yaml:"name"`
	Description          string                   `yaml:"description"`
	Severity             policy.Severity          `yaml:"severity,omitempty"`
	Domain               kernel.AssetDomain       `yaml:"domain,omitempty"`
	ScopeTags            []string                 `yaml:"scope_tags,omitempty"`
	Compliance           policy.ComplianceMapping `yaml:"compliance,omitempty"`
	Type                 policy.ControlType       `yaml:"type"`
	Params               map[string]any           `yaml:"params"`
	UnsafePredicate      yamlUnsafePredicate      `yaml:"unsafe_predicate"`
	UnsafePredicateAlias string                   `yaml:"unsafe_predicate_alias,omitempty"`
	Remediation          *yamlRemediationSpec     `yaml:"remediation,omitempty"`
	Exposure             *yamlExposure            `yaml:"exposure,omitempty"`
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
