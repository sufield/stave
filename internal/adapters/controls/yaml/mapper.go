package yaml

import (
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/exposure"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
	"github.com/sufield/stave/pkg/alpha/domain/predicate"
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
	return policy.NewRemediationSpec(y.Description, y.Action, y.Example)
}

func exposureToDomain(y *yamlExposure) *policy.Exposure {
	if y == nil {
		return nil
	}
	scope, _ := kernel.ParsePrincipalScope(y.PrincipalScope)
	return &policy.Exposure{
		Type:           exposure.Type(y.Type),
		PrincipalScope: scope,
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
