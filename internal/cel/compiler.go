package cel

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/google/cel-go/cel"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/predicate"
)

// CompiledPredicate holds a compiled CEL program and its source expression.
type CompiledPredicate struct {
	Program    cel.Program
	Expression string
}

// IsValid reports whether the predicate has a non-nil compiled program.
// Use to guard call sites that consume CompiledPredicate values built
// from heterogeneous sources (caches, decoders) where a zero-value
// struct could otherwise reach Eval and panic.
func (cp CompiledPredicate) IsValid() bool {
	return cp.Program != nil
}

// Compiler translates UnsafePredicate structures into compiled CEL programs.
// Compiled programs are cached by expression string for thread-safe reuse.
type Compiler struct {
	env   *cel.Env
	mu    sync.RWMutex
	cache map[string]CompiledPredicate
}

// NewCompiler creates a Compiler with a pre-configured CEL environment.
func NewCompiler() (*Compiler, error) {
	env, err := NewEnv()
	if err != nil {
		return nil, fmt.Errorf("create CEL environment: %w", err)
	}
	return &Compiler{
		env:   env,
		cache: make(map[string]CompiledPredicate),
	}, nil
}

// Compile translates an UnsafePredicate into a compiled CEL program.
// Results are cached by the generated expression string.
func (c *Compiler) Compile(pred policy.UnsafePredicate) (CompiledPredicate, error) {
	expr, err := predicateToExpr(pred, "")
	if err != nil {
		return CompiledPredicate{}, fmt.Errorf("predicate to expression: %w", err)
	}

	// Fast path: read-locked cache lookup.
	c.mu.RLock()
	cached, ok := c.cache[expr]
	c.mu.RUnlock()
	if ok {
		return cached, nil
	}

	// Compile under no lock — env.Compile is safe to call concurrently and
	// holding the write lock during compilation would serialize all
	// compiles across goroutines.
	ast, issues := c.env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return CompiledPredicate{}, fmt.Errorf("compile CEL expression: %w\n  expression: %s", issues.Err(), expr)
	}

	prg, err := c.env.Program(ast)
	if err != nil {
		return CompiledPredicate{}, fmt.Errorf("program CEL expression: %w", err)
	}

	result := CompiledPredicate{Program: prg, Expression: expr}

	// Double-checked write: another goroutine may have populated the
	// cache while we were compiling. Prefer the existing entry to keep
	// program identity stable for any callers that compared earlier.
	c.mu.Lock()
	if existing, exists := c.cache[expr]; exists {
		c.mu.Unlock()
		return existing, nil
	}
	c.cache[expr] = result
	c.mu.Unlock()

	return result, nil
}

// PredicateToExpr converts an UnsafePredicate to a CEL expression string.
// Exported for diagnostic use; callers should use Compile instead.
func PredicateToExpr(pred policy.UnsafePredicate) (string, error) {
	return predicateToExpr(pred, "")
}

// predicateToExpr converts an UnsafePredicate to a CEL expression string.
// scopeVar controls field resolution:
//   - "" (empty): top-level — fields like "properties.x" resolve normally
//   - "__id": inside any_match — bare fields like "type" resolve to __id["type"]
func predicateToExpr(pred policy.UnsafePredicate, scopeVar string) (string, error) {
	var parts []string

	if len(pred.Any) > 0 {
		anyExprs := make([]string, 0, len(pred.Any))
		for i := range pred.Any {
			e, err := ruleToExpr(&pred.Any[i], scopeVar)
			if err != nil {
				return "", fmt.Errorf("any[%d]: %w", i, err)
			}
			if e != "" {
				anyExprs = append(anyExprs, e)
			}
		}
		if len(anyExprs) > 0 {
			parts = append(parts, "("+strings.Join(anyExprs, " || ")+")")
		}
	}

	if len(pred.All) > 0 {
		allExprs := make([]string, 0, len(pred.All))
		for i := range pred.All {
			e, err := ruleToExpr(&pred.All[i], scopeVar)
			if err != nil {
				return "", fmt.Errorf("all[%d]: %w", i, err)
			}
			if e != "" {
				allExprs = append(allExprs, e)
			}
		}
		if len(allExprs) > 0 {
			parts = append(parts, "("+strings.Join(allExprs, " && ")+")")
		}
	}

	if len(parts) == 0 {
		// An empty predicate (no any[], no all[], or every nested rule
		// reduced to "") would compile to the literal "false" — every
		// asset evaluates as "safe" silently. That's the worst possible
		// failure mode for a security control: the YAML loaded, the
		// CEL compiled, and nothing ever violates regardless of state.
		// Surface the malformed predicate so the loader can reject the
		// control instead of evaluating against a no-op gate.
		return "", errors.New("empty predicate: at least one any/all rule must produce a non-empty expression")
	}
	return strings.Join(parts, " && "), nil
}

// ruleToExpr converts a single PredicateRule to a CEL expression.
// scopeVar is passed through for field resolution and recursive calls.
func ruleToExpr(r *policy.PredicateRule, scopeVar string) (string, error) {
	// Handle nested logic blocks (recursive any/all)
	if len(r.Any) > 0 || len(r.All) > 0 {
		nested := policy.UnsafePredicate{Any: r.Any, All: r.All}
		return predicateToExpr(nested, scopeVar)
	}

	field := r.Field.String()
	if field == "" {
		return "", nil
	}

	op := r.Op
	val := r.Value.Raw()

	// Resolve field access and existence check using current scope
	fa := scopedFieldAccess(field, scopeVar)
	hf := scopedHasField(field, scopeVar)

	// resolveValueExpr resolves values that reference params (e.g., "params.min_retention_days")
	// as CEL field accesses instead of string literals. The documented
	// `value_from_param` field takes precedence: if set, the rule
	// references a param by name and we emit `params.<name>` directly.
	// Otherwise we fall back to the legacy string-literal workaround
	// (`value: "params.foo"`) for backward compatibility.
	resolveValueExpr := func(v any) string {
		if r.ValueFromParam != "" {
			return "params." + string(r.ValueFromParam)
		}
		if s, ok := v.(string); ok && strings.HasPrefix(s, "params.") {
			return s // emit as-is — CEL resolves params.X from the activation map
		}
		return literal(v)
	}

	switch op {
	case predicate.OpEq:
		return fmt.Sprintf("(%s && %s == %s)", hf, fa, resolveValueExpr(val)), nil
	case predicate.OpNe:
		// Default: field must exist for inequality to be meaningful;
		// a missing field is not a violation. Backwards-compatible
		// "fail-open on missing" semantics.
		//
		// fail_on_missing=true flips the logic to fail-closed: the
		// missing field is itself the violation. Use for
		// security-critical controls where the absence of a
		// required field is more dangerous than its wrong value
		// (e.g. require_tls=true: missing → TLS might be off).
		if r.FailOnMissing {
			return fmt.Sprintf("(!(%s) || %s != %s)", hf, fa, resolveValueExpr(val)), nil
		}
		return fmt.Sprintf("(%s && %s != %s)", hf, fa, resolveValueExpr(val)), nil
	case predicate.OpGt:
		return fmt.Sprintf("(%s && %s > %s)", hf, fa, resolveValueExpr(val)), nil
	case predicate.OpLt:
		return fmt.Sprintf("(%s && %s < %s)", hf, fa, resolveValueExpr(val)), nil
	case predicate.OpGte:
		return fmt.Sprintf("(%s && %s >= %s)", hf, fa, resolveValueExpr(val)), nil
	case predicate.OpLte:
		return fmt.Sprintf("(%s && %s <= %s)", hf, fa, resolveValueExpr(val)), nil
	case predicate.OpIn:
		return fmt.Sprintf("(%s && %s in %s)", hf, fa, resolveValueExpr(val)), nil
	case predicate.OpContains:
		return fmt.Sprintf("(%s && string(%s).contains(%s))", hf, fa, resolveValueExpr(val)), nil
	case predicate.OpMissing:
		wantMissing, err := coerceBool(val, true)
		if err != nil {
			return "", fmt.Errorf("op missing: %w", err)
		}
		isMissing := fmt.Sprintf("(!(%s) || missing(%s))", hf, fa)
		if !wantMissing {
			return fmt.Sprintf("!(%s)", isMissing), nil
		}
		return isMissing, nil
	case predicate.OpPresent:
		wantPresent, err := coerceBool(val, true)
		if err != nil {
			return "", fmt.Errorf("op present: %w", err)
		}
		isPresent := fmt.Sprintf("(%s && !missing(%s))", hf, fa)
		if !wantPresent {
			return fmt.Sprintf("!(%s)", isPresent), nil
		}
		return isPresent, nil
	case predicate.OpListEmpty:
		// "empty" semantics:
		//   field absent          → true  (nothing there to be non-empty)
		//   collection size == 0  → true  (list/map/string with no elements)
		//   not a collection type → true  (an int / bool / number can't
		//                                  hold a list-shaped value, so
		//                                  it's logically empty for the
		//                                  purpose of this operator)
		//
		// The previous shape returned false for non-collection types,
		// causing controls that asked "is this list empty?" to fail
		// closed against legitimately-non-list extractor output.
		// size() in CEL errors on non-collection types, so the type()
		// guard must run *before* size() — short-circuiting with `!hf`
		// first, then collection-type membership, then size.
		return fmt.Sprintf(
			"(!(%s) || !(type(%s) in [type([]), type({}), type(\"\")]) || size(%s) == 0)",
			hf, fa, fa,
		), nil
	case predicate.OpNeqField:
		// Cross-field inequality. Both fields must exist for the
		// comparison to be meaningful — a missing target is treated as
		// "safe" (no violation by absence) so the negative operators
		// share a single, predictable convention.
		other := fmt.Sprint(val)
		ofa := scopedFieldAccess(other, scopeVar)
		ohf := scopedHasField(other, scopeVar)
		return fmt.Sprintf("(%s && %s && %s != %s)", hf, ohf, fa, ofa), nil
	case predicate.OpNotInField:
		// "source not in target list". Both fields must exist; missing
		// data does not produce a violation. Mirrors OpNeqField.
		other := fmt.Sprint(val)
		ofa := scopedFieldAccess(other, scopeVar)
		ohf := scopedHasField(other, scopeVar)
		return fmt.Sprintf("(%s && %s && !(%s in %s))", hf, ohf, fa, ofa), nil
	case predicate.OpNotSubsetOfField:
		// "source list not subset of target list". Both must exist;
		// missing data does not produce a violation. Mirrors the other
		// negative cross-field operators.
		other := fmt.Sprint(val)
		ofa := scopedFieldAccess(other, scopeVar)
		ohf := scopedHasField(other, scopeVar)
		return fmt.Sprintf("(%s && %s && %s.exists(x, !(x in %s)))", hf, ohf, fa, ofa), nil
	case predicate.OpAnyInField:
		// field.exists(x, x in other_field) — true when the field (a list)
		// has at least one element that also appears in another field's
		// list. Both sides must be present; either missing → false.
		// Complement of OpNotSubsetOfField.
		other := fmt.Sprint(val)
		ofa := scopedFieldAccess(other, scopeVar)
		ohf := scopedHasField(other, scopeVar)
		return fmt.Sprintf("(%s && %s && %s.exists(x, x in %s))", hf, ohf, fa, ofa), nil
	case predicate.OpAnyMatch:
		return ruleToExprAnyMatch(r, val, scopeVar, false)
	case predicate.OpAnyIdentityMatch:
		// Explicit identity-iteration shorthand. Field can be empty
		// or "identities" — both mean the same thing. The control
		// author writes `op: any_identity_match` so the iteration
		// target is unambiguous, instead of relying on the legacy
		// silent default that any_match used to apply.
		return ruleToExprAnyMatch(r, val, scopeVar, true)
	default:
		return "", fmt.Errorf("unsupported operator: %s", op)
	}
}

// coerceBool returns val as a Go bool. It accepts native bool and the
// case-insensitive strings "true"/"false" — YAML round-trips can leave a
// boolean literal as either, depending on whether the author quoted the
// value. nil falls back to defaultVal so callers can pick the
// "unspecified" semantics (e.g. op: missing with no value defaults to
// "field must be missing"). Any other type or unrecognized string is a
// compilation error rather than a silent default.
func coerceBool(val any, defaultVal bool) (bool, error) {
	switch v := val.(type) {
	case nil:
		return defaultVal, nil
	case bool:
		return v, nil
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		default:
			return false, fmt.Errorf("expected bool or \"true\"/\"false\" string, got %q", v)
		}
	default:
		return false, fmt.Errorf("expected bool or \"true\"/\"false\" string, got %T", val)
	}
}

// ruleToExprAnyMatch compiles an any_match rule into a CEL exists() macro.
// The nested predicate is compiled with "__id" scope so field references
// resolve against the iterator variable. The list to iterate is
// determined by r.Field — previously the implementation hardcoded
// "identities", which silently broke any_match on any other list field
// (per-resource lists, asset properties, etc.) by always testing the
// identities slot regardless of what the rule asked for.
//
// `identityShorthand=true` means the caller used the explicit
// any_identity_match operator: an empty Field defaults to
// `identities` without erroring. With identityShorthand=false (plain
// any_match), an empty Field is now an error — silent defaulting
// produced controls that compiled cleanly but iterated the wrong
// list.
func ruleToExprAnyMatch(r *policy.PredicateRule, val any, outerScope string, identityShorthand bool) (string, error) {
	var nested *policy.UnsafePredicate
	switch v := val.(type) {
	case *policy.UnsafePredicate:
		nested = v
	case policy.UnsafePredicate:
		nested = &v
	default:
		parsed, err := parseNestedPredicate(val)
		if err != nil {
			return "", fmt.Errorf("any_match: %w", err)
		}
		if parsed == nil {
			return "", errors.New("any_match: nil nested predicate")
		}
		nested = parsed
	}

	// Compile the nested predicate with "__id" scope — field references
	// like "type", "id", "purpose" will resolve to __id["type"], etc.
	innerExpr, err := predicateToExpr(*nested, "__id")
	if err != nil {
		return "", fmt.Errorf("any_match: %w", err)
	}
	if innerExpr == "" || innerExpr == "false" {
		return "", errors.New("any_match: empty nested predicate")
	}

	field := r.Field.String()
	if field == "" {
		if !identityShorthand {
			// Plain any_match without an explicit field used to
			// default silently to `identities`, which broke any
			// control that intended to iterate a different list.
			// Reject so the author rewrites with an explicit field
			// (or switches to any_identity_match).
			return "", errors.New("any_match: `field` is required (use `any_identity_match` for the identities-list shorthand)")
		}
		// any_identity_match: identities-list shorthand.
		return fmt.Sprintf("identities.exists(__id, %s)", innerExpr), nil
	}
	fa := scopedFieldAccess(field, outerScope)
	hf := scopedHasField(field, outerScope)
	return fmt.Sprintf("(%s && %s.exists(__id, %s))", hf, fa, innerExpr), nil
}

// parseNestedPredicate converts a raw value (map[string]any from YAML) into
// a typed UnsafePredicate. Uses YAML round-trip for correct struct mapping.
func parseNestedPredicate(v any) (*policy.UnsafePredicate, error) {
	if v == nil {
		return nil, nil
	}

	// The value is a map[string]any with keys "any" and/or "all".
	// We need to convert this into a policy.UnsafePredicate.
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("any_match value must be a map, got %T", v)
	}

	pred := &policy.UnsafePredicate{}
	if anyRules, hasAny := m["any"]; hasAny {
		rules, err := parseRuleList(anyRules)
		if err != nil {
			return nil, fmt.Errorf("any_match.any: %w", err)
		}
		pred.Any = rules
	}
	if allRules, hasAll := m["all"]; hasAll {
		rules, err := parseRuleList(allRules)
		if err != nil {
			return nil, fmt.Errorf("any_match.all: %w", err)
		}
		pred.All = rules
	}
	return pred, nil
}

// parseRuleList converts a raw []any (from YAML) into []PredicateRule.
func parseRuleList(v any) ([]policy.PredicateRule, error) {
	list, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("expected list, got %T", v)
	}

	rules := make([]policy.PredicateRule, 0, len(list))
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("rule must be a map, got %T", item)
		}

		rule := policy.PredicateRule{}

		if field, ok := m["field"].(string); ok {
			rule.Field = predicate.NewFieldPath(field)
		}
		if op, ok := m["op"].(string); ok {
			rule.Op = predicate.Operator(op)
		}
		if val, hasVal := m["value"]; hasVal {
			rule.Value = policy.NewOperand(val)
		}
		// `value_from_param` is the documented way to point a rule at
		// a control parameter (e.g. min_retention_days). The YAML round
		// trip into nested any_match blocks lost it because parseRuleList
		// only forwarded `field`/`op`/`value` — nested rules using
		// value_from_param compiled with no parameter binding and matched
		// against the literal string "params.X". Forward it here so
		// resolveValueExpr in ruleToExpr can emit the correct CEL.
		if vfp, ok := m["value_from_param"].(string); ok {
			rule.ValueFromParam = predicate.ParamRef(vfp)
		}
		if fom, ok := m["fail_on_missing"].(bool); ok {
			rule.FailOnMissing = fom
		}

		// Handle nested any/all blocks within the rule
		if anyBlock, hasAny := m["any"]; hasAny {
			nested, err := parseRuleList(anyBlock)
			if err != nil {
				return nil, err
			}
			rule.Any = nested
		}
		if allBlock, hasAll := m["all"]; hasAll {
			nested, err := parseRuleList(allBlock)
			if err != nil {
				return nil, err
			}
			rule.All = nested
		}

		rules = append(rules, rule)
	}
	return rules, nil
}
