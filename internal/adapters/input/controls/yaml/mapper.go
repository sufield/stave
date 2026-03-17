package yaml

import (
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/domain/predicate"
	"gopkg.in/yaml.v3"
)

// --- YAML DTO → Domain ---

func controlDefinitionToDomain(y yamlControlDefinition) policy.ControlDefinition {
	return policy.ControlDefinition{
		DSLVersion:           y.DSLVersion,
		ID:                   y.ID,
		Name:                 y.Name,
		Description:          y.Description,
		Severity:             y.Severity,
		Domain:               y.Domain,
		ScopeTags:            y.ScopeTags,
		Compliance:           y.Compliance,
		Type:                 y.Type,
		Params:               policy.NewParams(y.Params),
		UnsafePredicate:      unsafePredicateToDomain(y.UnsafePredicate),
		UnsafePredicateAlias: y.UnsafePredicateAlias,
		Remediation:          remediationToDomain(y.Remediation),
		Exposure:             exposureToDomain(y.Exposure),
	}
}

func unsafePredicateToDomain(y yamlUnsafePredicate) policy.UnsafePredicate {
	return policy.UnsafePredicate{
		Any: predicateRulesToDomain(y.Any),
		All: predicateRulesToDomain(y.All),
	}
}

func predicateRulesToDomain(rules []yamlPredicateRule) []policy.PredicateRule {
	if rules == nil {
		return nil
	}
	out := make([]policy.PredicateRule, len(rules))
	for i, r := range rules {
		out[i] = predicateRuleToDomain(r)
	}
	return out
}

func predicateRuleToDomain(y yamlPredicateRule) policy.PredicateRule {
	return policy.PredicateRule{
		Field:          predicate.NewFieldPath(y.Field),
		Op:             y.Op,
		Value:          policy.NewOperand(y.Value),
		ValueFromParam: predicate.ParamRef(y.ValueFromParam),
		Any:            predicateRulesToDomain(y.Any),
		All:            predicateRulesToDomain(y.All),
	}
}

func remediationToDomain(y *yamlRemediationSpec) *policy.RemediationSpec {
	if y == nil {
		return nil
	}
	return &policy.RemediationSpec{
		Description: y.Description,
		Action:      y.Action,
		Example:     y.Example,
	}
}

func exposureToDomain(y *yamlExposure) *policy.Exposure {
	if y == nil {
		return nil
	}
	scope, _ := kernel.ParsePrincipalScope(y.PrincipalScope)
	return &policy.Exposure{
		Type:           y.Type,
		PrincipalScope: scope,
	}
}

// --- Domain → YAML DTO ---

func controlDefinitionToYAML(d policy.ControlDefinition) yamlControlDefinition {
	return yamlControlDefinition{
		DSLVersion:           d.DSLVersion,
		ID:                   d.ID,
		Name:                 d.Name,
		Description:          d.Description,
		Severity:             d.Severity,
		Domain:               d.Domain,
		ScopeTags:            d.ScopeTags,
		Compliance:           d.Compliance,
		Type:                 d.Type,
		Params:               d.Params.Raw(),
		UnsafePredicate:      unsafePredicateToYAML(d.UnsafePredicate),
		UnsafePredicateAlias: d.UnsafePredicateAlias,
		Remediation:          remediationToYAML(d.Remediation),
		Exposure:             exposureToYAML(d.Exposure),
	}
}

func unsafePredicateToYAML(d policy.UnsafePredicate) yamlUnsafePredicate {
	return yamlUnsafePredicate{
		Any: predicateRulesToYAML(d.Any),
		All: predicateRulesToYAML(d.All),
	}
}

func predicateRulesToYAML(rules []policy.PredicateRule) []yamlPredicateRule {
	if rules == nil {
		return nil
	}
	out := make([]yamlPredicateRule, len(rules))
	for i, r := range rules {
		out[i] = predicateRuleToYAML(r)
	}
	return out
}

func predicateRuleToYAML(d policy.PredicateRule) yamlPredicateRule {
	return yamlPredicateRule{
		Field:          d.Field.String(),
		Op:             d.Op,
		Value:          d.Value.Raw(),
		ValueFromParam: d.ValueFromParam.String(),
		Any:            predicateRulesToYAML(d.Any),
		All:            predicateRulesToYAML(d.All),
	}
}

func remediationToYAML(d *policy.RemediationSpec) *yamlRemediationSpec {
	if d == nil {
		return nil
	}
	return &yamlRemediationSpec{
		Description: d.Description,
		Action:      d.Action,
		Example:     d.Example,
	}
}

func exposureToYAML(d *policy.Exposure) *yamlExposure {
	if d == nil {
		return nil
	}
	return &yamlExposure{
		Type:           d.Type,
		PrincipalScope: d.PrincipalScope.String(),
	}
}

// UnmarshalControlDefinition unmarshals YAML bytes into a domain ControlDefinition.
func UnmarshalControlDefinition(data []byte) (policy.ControlDefinition, error) {
	var dto yamlControlDefinition
	if err := yaml.Unmarshal(data, &dto); err != nil {
		return policy.ControlDefinition{}, err
	}
	return controlDefinitionToDomain(dto), nil
}

// MarshalControlYAML marshals a domain ControlDefinition into its canonical YAML wire format.
func MarshalControlYAML(ctl *policy.ControlDefinition) ([]byte, error) {
	dto := controlDefinitionToYAML(*ctl)
	return yaml.Marshal(dto)
}

// FormatControlYAML reformats raw YAML control bytes into canonical field order.
func FormatControlYAML(data []byte) ([]byte, error) {
	var dto yamlControlDefinition
	if err := yaml.Unmarshal(data, &dto); err != nil {
		return nil, err
	}
	return yaml.Marshal(dto)
}
