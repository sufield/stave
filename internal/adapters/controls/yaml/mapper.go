package yaml

import (
	"fmt"
	"strings"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/exposure"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
	"gopkg.in/yaml.v3"
)

// --- YAML DTO → Domain ---

// ToDomain promotes the YAML wire shape into the
// policy.ControlDefinition the engine consumes. Lives on the YAML
// DTO so the wire→domain conversion sits next to the type that
// owns the wire format — a future YAML schema change can be made
// in one place rather than hunting for a free-floating "mapper".
func (y yamlControlDefinition) ToDomain() (policy.ControlDefinition, error) {
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
		MitreAttack:          mitreAttackToDomain(y.MitreAttack),
		ValidatedAgainst:     labValidationToDomain(y.ValidatedAgainst),
		Tests:                y.Tests,
		Taxonomy:             y.Taxonomy,
		Defect:               y.Defect,
		Infection:            y.Infection,
		Failure:              y.Failure,
		Archetype:            kernel.ArchetypeID(strings.TrimSpace(y.Archetype)),
		Scope:                strings.TrimSpace(y.Scope),
		CorpusReference:      strings.TrimSpace(y.CorpusReference),
		IntentRationale:      strings.TrimSpace(y.IntentRationale),
		ForbiddenState:       unsafePredicateToDomain(y.ForbiddenState),
	}, nil
}

// controlDefinitionToDomain is retained as a thin wrapper around
// yamlControlDefinition.ToDomain for the loader's existing call
// shape. New code should prefer the method.
func controlDefinitionToDomain(y yamlControlDefinition) (policy.ControlDefinition, error) {
	return y.ToDomain()
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
		// Preserve the nil-vs-empty distinction so a downstream
		// reporter can tell "ccm_v4 was present but coercion
		// failed" (nil) apart from "ccm_v4 was present and
		// explicitly empty" ([]string{}). The previous shape
		// collapsed both states into []string{} and hid coercion
		// failures behind an apparently-clean empty list.
		ccm = coerceStringList(v)
	}
	mapping := make(policy.ComplianceMapping, len(raw))
	for k, v := range raw {
		if k == "ccm_v4" {
			continue
		}
		if s, ok := v.(string); ok {
			mapping[policy.ComplianceFramework(k)] = policy.RequirementID(s)
		}
	}
	if len(mapping) == 0 {
		return nil, ccm
	}
	return mapping, ccm
}

// coerceStringList coerces a YAML node value into []string.
//
// Returns nil when the input is neither []string nor []any — the
// caller in splitComplianceBlock relies on the nil-vs-non-nil
// distinction to surface coercion failures (see ccm_v4 handling
// above).
//
// Non-string elements inside a []any are SILENTLY DROPPED. This is
// intentional: the schema validator earlier in the load pipeline
// already rejects YAML where a list element has the wrong type,
// so anything reaching this function with a mixed list is a test
// fixture / programmatic call that bypassed validation. If a
// strict mode is ever needed, gate the drop behind a flag and
// return an error here.
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
			// Non-string element: silently dropped — see func
			// docstring for the schema-validator-upstream contract.
		}
		return out
	default:
		return nil
	}
}

func scopeTagsToDomain(tags []string) []kernel.ScopeTag {
	// Mirror assetTypesToDomain (and the rest of this file): treat
	// empty-non-nil and nil slices identically, returning nil. The
	// previous nil-only check produced an empty-but-non-nil slice
	// for `tags := []string{}`, which downstream consumers compared
	// against nil and silently mishandled.
	if len(tags) == 0 {
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

// isPredicateRulesEmpty reports whether the YAML predicate-rules
// input represents "no rules configured." Treats both nil and
// empty-non-nil slices as the same business state — the YAML
// loader can produce either depending on whether the field was
// omitted (`<missing>` → nil) or explicitly set to an empty list
// (`any: []` → non-nil zero-length). Sibling predicate to
// alternativesToDomain / scopeTagsToDomain / assetTypesToDomain so
// the empty-input policy lives on a named concept the mapper sites
// can reference.
func isPredicateRulesEmpty(rules []yamlPredicateRule) bool {
	return len(rules) == 0
}

func predicateRulesToDomain(rules []yamlPredicateRule) []policy.PredicateRule {
	if isPredicateRulesEmpty(rules) {
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
		Type:           asCatalogExposureType(y.Type),
		PrincipalScope: scope,
	}, nil
}

// asCatalogExposureType casts a raw YAML string into exposure.Type
// without runtime validation. The vocabulary is intentionally open
// at the type level: the catalog ships ~30 distinct values the
// classifier recognises (subdomain_takeover, cdn_bypass,
// latent_public_read, etc.) and the closed-set enforcement lives in
// the catalog linter / schema validator, not this mapper. Naming
// the cast documents that design choice so a future maintainer
// doesn't try to "tighten" exposureToDomain by validating against
// the named exposure.Type* constants — which would reject
// legitimate catalog entries.
func asCatalogExposureType(raw string) exposure.Type {
	return exposure.Type(raw)
}

func mitreAttackToDomain(in []yamlMitreAttack) []policy.MitreAttackRef {
	if len(in) == 0 {
		return nil
	}
	out := make([]policy.MitreAttackRef, len(in))
	for i, m := range in {
		out[i] = policy.MitreAttackRef{
			ID:     m.ID,
			Name:   m.Name,
			Tactic: m.Tactic,
		}
	}
	return out
}

func labValidationToDomain(in []yamlLabValidation) []policy.LabValidation {
	if len(in) == 0 {
		return nil
	}
	out := make([]policy.LabValidation, len(in))
	for i, v := range in {
		out[i] = policy.LabValidation{
			Vendor:   v.Vendor,
			Lab:      v.Lab,
			Result:   v.Result,
			Verified: v.Verified,
		}
	}
	return out
}

// UnmarshalControlDefinition unmarshals YAML bytes into a domain ControlDefinition.
func UnmarshalControlDefinition(data []byte) (policy.ControlDefinition, error) {
	var dto yamlControlDefinition
	if err := yaml.Unmarshal(data, &dto); err != nil {
		return policy.ControlDefinition{}, fmt.Errorf("unmarshal control YAML: %w", err)
	}
	return controlDefinitionToDomain(dto)
}
