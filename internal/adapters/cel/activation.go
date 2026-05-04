package cel

import (
	"fmt"
	"log/slog"
)

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
// `identity` resolves to the first identity in the slice when one is
// present and well-typed; missing or malformed inputs fall back to
// an empty map (see resolvePrimaryIdentity for the resolution
// policy). The fallback was historically the source of confusing
// "predicate evaluated against {} → false on every asset" outcomes
// when collectors handed in wrong-shape identities.
func NewActivation(properties, params map[string]any, identities []any) Activation {
	// Mirror the params guard: a nil properties map dereferences to
	// an unknown-field error in CEL, surfacing as a confusing
	// "no such key" rather than the cleaner "field absent" semantic
	// the rest of the engine relies on.
	if properties == nil {
		properties = map[string]any{}
	}
	if params == nil {
		params = map[string]any{}
	}
	return Activation{
		"properties": properties,
		"params":     params,
		"identities": identities,
		"identity":   resolvePrimaryIdentity(identities),
	}
}

// resolvePrimaryIdentity extracts the first identity from the raw
// slice and ensures it is a structured map. Three possible inputs:
//
//   - empty slice / nil entry: no identity supplied → empty map
//   - first entry is a map[string]any: structured identity → use it
//   - first entry is non-nil but not a map: upstream type mismatch
//     → empty map + slog.Warn so the shape bug doesn't hide behind
//     "predicate evaluated against {} → false"
//
// Lifted out of NewActivation so the constructor expresses *what*
// the activation contains, while this helper expresses *how* the
// raw identity slice is normalised into the structured form
// predicates can read.
func resolvePrimaryIdentity(identities []any) map[string]any {
	if len(identities) == 0 {
		return map[string]any{}
	}
	raw := identities[0]
	if raw == nil {
		return map[string]any{}
	}
	if structured, ok := raw.(map[string]any); ok {
		return structured
	}
	slog.Warn("cel.NewActivation: primary identity is not a map; falling back to empty",
		"actual_type", fmt.Sprintf("%T", raw))
	return map[string]any{}
}
