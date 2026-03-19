package cel

import (
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// NewEnv creates a CEL environment configured for Stave predicate evaluation.
//
// The environment provides:
//   - "properties" as map<string, dyn> — the asset's property tree
//   - "params" as map<string, dyn> — control parameters
//   - "identities" as list<dyn> — cloud identities for any_match
//   - "identity" as map<string, dyn> — single identity context
//   - missing(field) — custom function matching Stave's three-way absence check
func NewEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable("properties", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("params", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("identities", cel.ListType(cel.DynType)),
		cel.Variable("identity", cel.MapType(cel.StringType, cel.DynType)),

		// missing(value) — returns true if value is null, empty string,
		// empty list, or empty map. Matches Stave's IsEmptyValue semantics.
		cel.Function("missing",
			cel.Overload("missing_dyn",
				[]*cel.Type{cel.DynType},
				cel.BoolType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					return types.Bool(isMissing(val))
				}),
			),
		),
	)
}

// isMissing implements Stave's three-way absence semantics:
// null, empty string (trimmed), empty list, empty map.
func isMissing(val ref.Val) bool {
	if val == nil || val == types.NullValue {
		return true
	}

	switch v := val.Value().(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(v) == ""
	case []any:
		return len(v) == 0
	case map[string]any:
		return len(v) == 0
	default:
		// Check for CEL list/map types
		if sizer, ok := val.(interface{ Size() ref.Val }); ok {
			if sz, ok := sizer.Size().Value().(int64); ok {
				return sz == 0
			}
		}
		return false
	}
}

// fieldAccess generates a CEL expression for accessing a dot-path field
// using bracket indexing on dynamic maps.
//
// Example: "properties.storage.versioning.enabled" becomes
//
//	properties["storage"]["versioning"]["enabled"]
func fieldAccess(dotPath string) string {
	parts := strings.Split(dotPath, ".")
	if len(parts) <= 1 {
		return dotPath
	}
	var result strings.Builder
	result.WriteString(parts[0])
	for _, p := range parts[1:] {
		fmt.Fprintf(&result, "[%q]", p)
	}
	return result.String()
}

// hasField generates a CEL existence check for a dot-path using the "in"
// operator at each nesting level.
//
// Example: "properties.storage.versioning.enabled" becomes
//
//	"storage" in properties &&
//	"versioning" in properties["storage"] &&
//	"enabled" in properties["storage"]["versioning"]
func hasField(dotPath string) string {
	parts := strings.Split(dotPath, ".")
	if len(parts) <= 1 {
		// Top-level variable — always exists in the activation
		return "true"
	}

	checks := make([]string, 0, len(parts)-1)
	for i := 1; i < len(parts); i++ {
		var base strings.Builder
		base.WriteString(parts[0])
		for j := 1; j < i; j++ {
			fmt.Fprintf(&base, "[%q]", parts[j])
		}
		checks = append(checks, fmt.Sprintf("%q in %s", parts[i], base.String()))
	}
	return strings.Join(checks, " && ")
}
