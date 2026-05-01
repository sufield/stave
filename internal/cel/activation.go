package cel

// Activation is the named-key bag of values passed to a compiled CEL
// program. Encodes the contract between the predicate compiler (which
// emits expressions like `properties.foo`, `params.bar`,
// `identities[0]`, `identity.kind`) and the evaluator that supplies the
// matching keys.
//
// The map literal at evaluator.go used to be anonymous — a missing key
// or a typo on either side would compile fine and silently misbehave
// at runtime. Naming the type makes the contract a build-time concern
// and gives reviewers something to hover over.
type Activation map[string]any

// NewActivation builds the standard activation expected by every
// compiled predicate: properties from the asset, identities + a
// single-identity convenience handle, and the control's params.
//
// `identity` is the *first* identity when present, or an empty map
// otherwise. Hardcoding an empty map silently masked all per-identity
// field reads in single-identity controls — predicates like
// `identity.type == "service_role"` evaluated against `{}`, returning
// false on every asset regardless of input.
func NewActivation(properties, params map[string]any, identities []any) Activation {
	identity := map[string]any{}
	if len(identities) > 0 {
		if first, ok := identities[0].(map[string]any); ok {
			identity = first
		}
	}
	if params == nil {
		params = map[string]any{}
	}
	return Activation{
		"properties": properties,
		"params":     params,
		"identities": identities,
		"identity":   identity,
	}
}
