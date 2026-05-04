package controldef

import "github.com/sufield/stave/internal/core/asset"

// PredicateParser defines a function that can expand a raw value into a nested logic tree.
type PredicateParser func(v any) (*UnsafePredicate, error)

// UnsafePredicate defines the logical conditions required to classify a resource as unsafe.
type UnsafePredicate struct {
	// Any matches if at least one rule evaluates to true (Logical OR).
	Any []PredicateRule `json:"any,omitempty"`
	// All matches only if every rule evaluates to true (Logical AND).
	All []PredicateRule `json:"all,omitempty"`
}

// IsEmpty reports whether this predicate carries no rules at all
// (neither Any nor All populated). Encapsulates the slice-length pair
// so call sites that gate on "the predicate has nothing to evaluate"
// stop reaching into the internal Any/All shape — a future third
// rule category (None, etc.) lands here once instead of at every
// validation/parser site.
//
// Value receiver matches the rest of UnsafePredicate's method set
// (Walk, MissingParamReferences). Callers with a *UnsafePredicate
// should nil-check before invoking.
func (p UnsafePredicate) IsEmpty() bool {
	return len(p.Any) == 0 && len(p.All) == 0
}

// PredicateEval evaluates whether an asset is unsafe according to a control's
// predicate. This function type decouples evaluation consumers from the
// evaluation engine implementation (CEL or built-in).
type PredicateEval func(ctl ControlDefinition, a asset.Asset, identities []asset.CloudIdentity) (unsafe bool, err error)

// EvalContext encapsulates all state available to a predicate during evaluation.
type EvalContext struct {
	properties      map[string]any
	CloudIdentity   *asset.CloudIdentity
	Identities      []asset.CloudIdentity
	Params          ControlParams
	PredicateParser PredicateParser
}

// GetProperty returns the property at key. ok is false when the key
// is not present, which is distinct from "present with nil value".
func (c *EvalContext) GetProperty(key string) (any, bool) {
	v, ok := c.properties[key]
	return v, ok
}

// SetProperty stores val under key. Allocates the backing map on
// first write so the zero-value EvalContext is usable.
func (c *EvalContext) SetProperty(key string, val any) {
	if c.properties == nil {
		c.properties = make(map[string]any, 1)
	}
	c.properties[key] = val
}

// PropertyMap returns the underlying property map for predicate
// evaluators that need to walk dotted property paths. The returned
// map is the live backing map; callers that need a mutation-safe
// view should clone it.
func (c *EvalContext) PropertyMap() map[string]any {
	return c.properties
}

// NewAssetEvalContext builds a context focused on resource properties.
func NewAssetEvalContext(a asset.Asset, params ControlParams, parser PredicateParser, identities ...asset.CloudIdentity) *EvalContext {
	ids := make([]asset.CloudIdentity, len(identities))
	copy(ids, identities)

	return &EvalContext{
		properties:      a.Map(),
		Params:          params,
		Identities:      ids,
		PredicateParser: parser,
	}
}
