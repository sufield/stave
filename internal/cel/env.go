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

// knownNamespaces are the top-level CEL variables in the activation.
// Field paths that don't start with one of these are treated as property
// lookups (prefixed with "properties" to match the old evaluator's
// default-namespace behavior).
var knownNamespaces = map[string]bool{
	"properties": true,
	"params":     true,
	"identities": true,
	"identity":   true,
}

// normalizePath ensures the field path starts with a known CEL namespace.
// Bare fields like "type" become "properties.type" to match the old
// evaluator's default-namespace resolution.
func normalizePath(dotPath string) string {
	first, _, _ := strings.Cut(dotPath, ".")
	if knownNamespaces[first] {
		return dotPath
	}
	return "properties." + dotPath
}

// fieldAccess generates a CEL expression for accessing a dot-path field
// using bracket indexing on dynamic maps.
//
// Example: "properties.storage.versioning.enabled" becomes
//
//	properties["storage"]["versioning"]["enabled"]
//
// Bare fields like "type" are normalized to "properties.type" first.
func fieldAccess(dotPath string) string {
	dotPath = normalizePath(dotPath)
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
//
// Bare fields like "type" are normalized to "properties.type" first.
func hasField(dotPath string) string {
	dotPath = normalizePath(dotPath)
	parts := strings.Split(dotPath, ".")
	if len(parts) <= 1 {
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

// --- Scope-aware field helpers ---

// scopedFieldAccess generates a CEL field access expression.
// When scopeVar is empty, uses the field's first segment as the root variable.
// When scopeVar is set (e.g., "__id"), all segments are indexed from that variable.
func scopedFieldAccess(dotPath, scopeVar string) string {
	if scopeVar == "" {
		return fieldAccess(dotPath)
	}
	// In scoped mode, the entire field path is relative to scopeVar.
	// "type" → __id["type"]
	// "purpose" → __id["purpose"]
	// "grants.has_wildcard" → __id["grants"]["has_wildcard"]
	parts := strings.Split(dotPath, ".")
	var result strings.Builder
	result.WriteString(scopeVar)
	for _, p := range parts {
		fmt.Fprintf(&result, "[%q]", p)
	}
	return result.String()
}

// scopedHasField generates a CEL existence check for a field.
// When scopeVar is empty, uses the standard hasField logic.
// When scopeVar is set, checks each segment relative to scopeVar.
func scopedHasField(dotPath, scopeVar string) string {
	if scopeVar == "" {
		return hasField(dotPath)
	}
	// In scoped mode, check existence at each nesting level from scopeVar.
	// "type" → "type" in __id
	// "grants.has_wildcard" → "grants" in __id && "has_wildcard" in __id["grants"]
	parts := strings.Split(dotPath, ".")
	checks := make([]string, 0, len(parts))
	for i := range parts {
		var base strings.Builder
		base.WriteString(scopeVar)
		for j := range i {
			fmt.Fprintf(&base, "[%q]", parts[j])
		}
		checks = append(checks, fmt.Sprintf("%q in %s", parts[i], base.String()))
	}
	return strings.Join(checks, " && ")
}

// literal converts a Go value to a CEL literal string.
// String values "true"/"false" are emitted as boolean literals to match
// the observation property normalizer's coercion behavior.
func literal(v any) string {
	switch val := v.(type) {
	case bool:
		if val {
			return "true"
		}
		return "false"
	case string:
		// Normalize boolean strings to match property normalizer
		switch strings.ToLower(strings.TrimSpace(val)) {
		case "true":
			return "true"
		case "false":
			return "false"
		}
		return fmt.Sprintf("%q", val)
	case float64:
		if val == float64(int64(val)) {
			return fmt.Sprintf("%d", int64(val))
		}
		return fmt.Sprintf("%g", val)
	case int:
		return fmt.Sprintf("%d", val)
	case int64:
		return fmt.Sprintf("%d", val)
	case []string:
		quoted := make([]string, len(val))
		for i, s := range val {
			quoted[i] = fmt.Sprintf("%q", s)
		}
		return "[" + strings.Join(quoted, ", ") + "]"
	case []any:
		items := make([]string, len(val))
		for i, item := range val {
			items[i] = literal(item)
		}
		return "[" + strings.Join(items, ", ") + "]"
	case nil:
		return "null"
	default:
		return fmt.Sprintf("%v", val)
	}
}
