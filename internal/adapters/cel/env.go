package cel

import (
	"fmt"
	"log/slog"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
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
	env, err := cel.NewEnv(
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
					if IsTypeError(val) {
						return val
					}
					return types.Bool(isMissing(val))
				}),
			),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("create CEL environment: %w", err)
	}
	return env, nil
}

// missingErrorPatterns lists substrings that cel-go uses (across versions)
// to signal "field or key not present in data". Add new phrasings here if
// a cel-go upgrade introduces a new structural-absence wording. Function
// overload errors ("no such overload", "no matching overload") are NOT
// included — those signal a type mismatch (e.g. calling size() on an int
// or comparing a string to a list) and must surface as evaluation
// failures so the predicate is flagged as inconclusive rather than
// silently passing.
var missingErrorPatterns = []string{
	"no such key",
	"undefined field",
	"no such attribute",
}

// typeErrorPatterns lists substrings that cel-go emits for type errors —
// failed function-overload resolution and incompatible-type comparisons.
// Distinct from missingErrorPatterns: a type error means the predicate
// asked the wrong question of the data, which is a programming defect,
// not absence.
var typeErrorPatterns = []string{
	"no such overload",
	"no matching overload",
}

// IsTypeError reports whether a CEL ref.Val carries a cel-go type error
// (overload-resolution failure or incompatible-type comparison). Use
// this at evaluation boundaries to distinguish a flawed predicate (type
// error → inconclusive) from a legitimately absent field
// (missingErrorPatterns → handled by isMissing).
func IsTypeError(val ref.Val) bool {
	if val == nil || !types.IsError(val) {
		return false
	}
	errVal, ok := val.Value().(error)
	if !ok {
		return false
	}
	msg := errVal.Error()
	for _, pattern := range typeErrorPatterns {
		if strings.Contains(msg, pattern) {
			return true
		}
	}
	return false
}

// isCollectionEmpty reports whether a CEL collection (list or map)
// is empty OR has an unmeasurable size. Returning true on a Size()
// error is a fail-safe policy: a malformed lister/mapper wrapper
// that can't report its length would otherwise compare unequal to
// IntZero and let the caller treat unparseable data as "populated"
// — bypassing missing-data predicates that gate downstream
// evaluation. Treating "unmeasurable" as "absent" keeps that path
// closed.
//
// Both lister and mapper isMissing branches funnel through this
// helper so the empty-vs-error policy lives in one place.
func isCollectionEmpty(size ref.Val) bool {
	if types.IsError(size) {
		return true
	}
	return size.Equal(types.IntZero) == types.True
}

// isMissing implements Stave's three-way absence semantics:
// null, empty string (trimmed), empty list, empty map, structural CEL
// error. Runtime errors (division by zero, type mismatch, overload
// resolution failure) are NOT treated as missing — they indicate a
// flawed predicate that must surface as inconclusive. Use IsTypeError
// at evaluation boundaries to distinguish those from legitimate absence.
func isMissing(val ref.Val) bool {
	if val == nil || val == types.NullValue {
		return true
	}
	// CEL error — match only structural-absence phrasings. Type errors
	// (overload mismatch, comparisons between incompatible types) and
	// runtime errors (div-by-zero) deliberately fall through to "not
	// missing" so callers see them as inconclusive instead of silent
	// passes.
	if types.IsError(val) {
		errVal, ok := val.Value().(error)
		if !ok {
			return false // unexpected error type — not missing
		}
		msg := errVal.Error()
		for _, pattern := range missingErrorPatterns {
			if strings.Contains(msg, pattern) {
				return true
			}
		}
		// Type errors (overload mismatch) and runtime errors
		// (div-by-zero) intentionally read as "not missing" so the
		// evaluator sees them as inconclusive. Log the unmatched
		// error path so a future runtime error pattern that *should*
		// have been classified as missing-data is visible to
		// operators rather than silently buried in "not missing".
		if !IsTypeError(val) {
			slog.Debug("isMissing: unrecognized CEL error pattern; treating as inconclusive",
				"error", msg)
		}
		return false
	}

	// CEL-internal collection types implement traits.Lister and
	// traits.Mapper. A CEL expression like `properties.tags` returns a
	// CEL map wrapper, not a Go map[string]any — the explicit trait
	// check classifies those wrappers correctly. Native Go branches
	// below cover values injected directly into the activation
	// (Properties / Params / etc.) before they pass through CEL.
	if lister, ok := val.(traits.Lister); ok {
		return isCollectionEmpty(lister.Size())
	}
	if mapper, ok := val.(traits.Mapper); ok {
		return isCollectionEmpty(mapper.Size())
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
	if dotPath == "" {
		// An empty path cannot exist. Returning "true" used to
		// short-circuit predicates against malformed control YAML
		// into a false-pass — prefer "false" so the rule visibly
		// fails rather than silently passing.
		return "false"
	}
	parts := strings.Split(dotPath, ".")
	if len(parts) == 1 {
		// Single-segment path after normalization is always a known
		// top-level CEL variable (properties, params, identities,
		// identity); normalizePath prefixes anything else with
		// "properties.". Those four are declared in NewEnv AND
		// always supplied by NewActivation (with nil-normalization
		// to empty maps), so a top-level variable is guaranteed
		// present at evaluation time.
		//
		// The earlier shape emitted `size(x) >= 0` as a defensive
		// runtime probe — that expression is functionally equivalent
		// to `true` for any non-error binding (size returns a
		// non-negative int) and CEL-errors for an undefined binding,
		// surfacing the gap as an evaluation error rather than a
		// silent true. The activation guarantee added in L-batch's
		// NewActivation nil-normalization makes the defensive probe
		// unreachable: every top-level variable now has a concrete
		// (possibly empty) map. Return "true" directly so the
		// emitted CEL is honest about what it's asserting.
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

// fieldExprs bundles the access expression and existence-guard
// expression that always travel together when CEL emits a
// scope-aware field reference. Names the previously anonymous
// (access, exists) tuple so call sites read what each half is for.
type fieldExprs struct {
	access string
	exists string
}

// scopedFieldExprs returns the (access, exists) pair for a dotted path
// resolved against scopeVar. Wraps scopedFieldAccess + scopedHasField
// so callers that need both halves don't compute them in parallel.
func scopedFieldExprs(dotPath, scopeVar string) fieldExprs {
	return fieldExprs{
		access: scopedFieldAccess(dotPath, scopeVar),
		exists: scopedHasField(dotPath, scopeVar),
	}
}

// scopedFieldAccess generates a CEL field access expression.
// When scopeVar is empty, uses the field's first segment as the root variable.
// When scopeVar is set (e.g., "__id"), all segments are indexed from that variable.
func scopedFieldAccess(dotPath, scopeVar string) string {
	if dotPath == "" {
		// An empty path is a degenerate case: the caller is asking
		// for the scope root itself. Without this guard the
		// strings.Split below produces [""] and the loop emits
		// `__id[""]`, which is a CEL error rather than the root
		// reference the caller wanted. scopedHasField already has
		// this guard (line 303); mirror it here for consistency.
		return scopeVar
	}
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
	if dotPath == "" {
		// An empty path cannot exist. Mirrors the non-scoped
		// hasField guard: returning "false" prevents the regex
		// engine from emitting `"" in __id`, which would compile
		// to an always-true membership check (every map "contains"
		// the empty string in CEL? actually false, but the
		// expression is invalid YAML for this context). False is
		// the safe / correct verdict for an empty path.
		return "false"
	}
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

// safeIntegerBound is the half-open range outside which a float
// cannot be safely converted to int64. IEEE 754 doubles can
// represent every integer up to 2^53 exactly; beyond that the
// rounding mode of float→int conversion would silently change the
// value. Reject values outside [-2^53, 2^53] so the literal step
// surfaces the imprecision instead of emitting a misleading
// integer literal.
const safeIntegerBound = float64(1 << 53)

// isWholeIntegerFloat reports whether a float64 value is exactly
// representable as an int64 inside the safeIntegerBound range AND
// has no fractional component. Used by the literal() float
// branches to decide between integer and float CEL syntax. The
// math.Trunc check guards against fractional values; the bound
// check guards against precision loss outside ±2^53.
func isWholeIntegerFloat(v float64) bool {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return false
	}
	if v < -safeIntegerBound || v > safeIntegerBound {
		return false
	}
	return math.Trunc(v) == v
}

// literal converts a Go value to a CEL literal string.
// String values "true"/"false" are emitted as boolean literals to match
// the observation property normalizer's coercion behavior.
//
// Unsupported types fail with a descriptive error rather than the
// previous fmt.Sprintf("%v") fallback, which silently produced
// uncompilable CEL fragments (e.g. a struct printed as `{x:1}` is not
// valid CEL syntax). The compile error then surfaces far from the
// rule that triggered it. Surface the type mismatch at the literal
// step so the failing rule is named in the error path.
func literal(v any) (string, error) {
	switch val := v.(type) {
	case bool:
		if val {
			return "true", nil
		}
		return "false", nil
	case string:
		// Normalize boolean strings to match property normalizer
		switch strings.ToLower(strings.TrimSpace(val)) {
		case "true":
			return "true", nil
		case "false":
			return "false", nil
		}
		return fmt.Sprintf("%q", val), nil
	case float64:
		if isWholeIntegerFloat(val) {
			return strconv.FormatInt(int64(val), 10), nil
		}
		return fmt.Sprintf("%g", val), nil
	case float32:
		// Promote float32 values into the float64 path: CEL has a
		// single double type, so the textual representation is the
		// same. The earlier shape only handled float64 and would
		// reject float32 values from tests or non-JSON sources.
		f := float64(val)
		if isWholeIntegerFloat(f) {
			return strconv.FormatInt(int64(f), 10), nil
		}
		return fmt.Sprintf("%g", f), nil
	case int:
		return strconv.Itoa(val), nil
	case int32:
		return strconv.FormatInt(int64(val), 10), nil
	case int64:
		return strconv.FormatInt(val, 10), nil
	case uint:
		return strconv.FormatUint(uint64(val), 10), nil
	case uint32:
		return strconv.FormatUint(uint64(val), 10), nil
	case uint64:
		return strconv.FormatUint(val, 10), nil
	case []string:
		quoted := make([]string, len(val))
		for i, s := range val {
			quoted[i] = fmt.Sprintf("%q", s)
		}
		return "[" + strings.Join(quoted, ", ") + "]", nil
	case []any:
		items := make([]string, len(val))
		for i, item := range val {
			lit, err := literal(item)
			if err != nil {
				return "", fmt.Errorf("list[%d]: %w", i, err)
			}
			items[i] = lit
		}
		return "[" + strings.Join(items, ", ") + "]", nil
	case map[string]any:
		// Emit as a CEL map literal with sorted keys for deterministic output.
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		entries := make([]string, len(keys))
		for i, k := range keys {
			lit, err := literal(val[k])
			if err != nil {
				return "", fmt.Errorf("map[%q]: %w", k, err)
			}
			entries[i] = fmt.Sprintf("%q: %s", k, lit)
		}
		return "{" + strings.Join(entries, ", ") + "}", nil
	case nil:
		return "null", nil
	default:
		return "", fmt.Errorf("unsupported literal type %T for CEL expression", v)
	}
}
