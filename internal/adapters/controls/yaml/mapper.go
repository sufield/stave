package yaml

import (
	"fmt"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/exposure"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
	"gopkg.in/yaml.v3"
)

// --- YAML DTO → Domain ---

func controlDefinitionToDomain(y yamlControlDefinition) (policy.ControlDefinition, error) {
	mapping, ccmV4 := splitComplianceBlock(y.Compliance)
	exp, err := exposureToDomain(y.Exposure)
	if err != nil {
		return policy.ControlDefinition{}, fmt.Errorf("control %q: %w", y.ID, err)
	}
	return policy.ControlDefinition{
		DSLVersion:           y.DSLVersion,
		ID:                   y.ID,
		Name:                 y.Name,
		Description:          y.Description,
		Severity:             y.Severity,
		Domain:               y.Domain,
		ScopeTags:            scopeTagsToDomain(y.ScopeTags),
		ApplicableAssetTypes: assetTypesToDomain(y.ApplicableAssetTypes),
		Compliance:           mapping,
		CCMV4:                ccmV4,
		Type:                 y.Type,
		Classification:       policy.Classification(y.Classification),
		Params:               policy.NewParams(y.Params),
		UnsafePredicate:      unsafePredicateToDomain(y.UnsafePredicate),
		UnsafePredicateAlias: y.UnsafePredicateAlias,
		Remediation:          remediationToDomain(y.Remediation),
		Exposure:             exp,
		ObservationFields:    y.ObservationFields,
		Alternatives:         alternativesToDomain(y.Alternatives),
		Tests:                y.Tests,
		Defect:               y.Defect,
		Infection:            y.Infection,
		Failure:              y.Failure,
		Archetype:            y.Archetype,
	}, nil
}

// alternativesToDomain translates the YAML wire entries to domain values.
// Returns nil when the input is empty so absence and emptiness are
// indistinguishable downstream.
func alternativesToDomain(in []yamlAlternative) []policy.Alternative {
	if len(in) == 0 {
		return nil
	}
	out := make([]policy.Alternative, len(in))
	for i, a := range in {
		out[i] = policy.Alternative{
			Tool:     a.Tool,
			CheckID:  a.CheckID,
			Coverage: policy.CoverageStatus(a.Coverage),
			Note:     a.Note,
		}
	}
	return out
}

// splitComplianceBlock separates the special "ccm_v4" list from the rest of
// the compliance framework map. Framework keys map to a single string; the
// "ccm_v4" key is a list of CCM v4 control IDs. The JSON schema validator
// enforces value types upstream, so this is an unchecked split: non-list
// values at "ccm_v4" and non-string values at other keys are dropped here
// and reported as schema failures earlier in the load pipeline.
func splitComplianceBlock(raw map[string]any) (policy.ComplianceMapping, []string) {
	if len(raw) == 0 {
		return nil, nil
	}
	var ccm []string
	if v, ok := raw["ccm_v4"]; ok {
		ccm = coerceStringList(v)
		if ccm == nil {
			ccm = []string{}
		}
	}
	mapping := make(policy.ComplianceMapping, len(raw))
	for k, v := range raw {
		if k == "ccm_v4" {
			continue
		}
		if s, ok := v.(string); ok {
			mapping[policy.ComplianceFramework(k)] = s
		}
	}
	if len(mapping) == 0 {
		return nil, ccm
	}
	return mapping, ccm
}

func coerceStringList(v any) []string {
	switch s := v.(type) {
	case []string:
		out := make([]string, len(s))
		copy(out, s)
		return out
	case []any:
		out := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				out = append(out, str)
			}
		}
		return out
	default:
		return nil
	}
}

func scopeTagsToDomain(tags []string) []kernel.ScopeTag {
	if tags == nil {
		return nil
	}
	out := make([]kernel.ScopeTag, len(tags))
	for i, t := range tags {
		out[i] = kernel.ScopeTag(t)
	}
	return out
}

func assetTypesToDomain(types []string) []kernel.AssetType {
	if len(types) == 0 {
		return nil
	}
	out := make([]kernel.AssetType, len(types))
	for i, t := range types {
		out[i] = kernel.AssetType(t)
	}
	return out
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
		FailOnMissing:  y.FailOnMissing,
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

func exposureToDomain(y *yamlExposure) (*policy.Exposure, error) {
	if y == nil {
		return nil, nil
	}
	// A non-empty principal_scope that fails to parse used to log a
	// warning and silently fall back to the zero-value scope, which
	// downstream evaluation interpreted as "any principal." Operators
	// who typed `principal_scope: cross_acount` (typo) thereby
	// defaulted into the most permissive interpretation. Now an
	// explicit non-empty value must parse cleanly or the control fails
	// validation, so authoring mistakes surface at load.
	scope, err := kernel.ParsePrincipalScope(y.PrincipalScope)
	if err != nil && y.PrincipalScope != "" {
		return nil, fmt.Errorf("invalid principal_scope %q: %w", y.PrincipalScope, err)
	}
	return &policy.Exposure{
		Type:           exposure.Type(y.Type),
		PrincipalScope: scope,
	}, nil
}

// UnmarshalControlDefinition unmarshals YAML bytes into a domain ControlDefinition.
func UnmarshalControlDefinition(data []byte) (policy.ControlDefinition, error) {
	var dto yamlControlDefinition
	if err := yaml.Unmarshal(data, &dto); err != nil {
		return policy.ControlDefinition{}, err
	}
	return controlDefinitionToDomain(dto)
}
