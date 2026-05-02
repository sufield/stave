package cel

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/google/cel-go/cel"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/predicate"
)

// CELExpression is a compiled CEL source string. Typed alias so the
// compile/cache layer carries the meaning end-to-end and so the
// expression string never accidentally mixes with arbitrary user
// strings (predicate keys, parameter values, etc.).
type CELExpression string

// String returns the raw expression source.
func (e CELExpression) String() string { return string(e) }

// CompiledPredicate holds a compiled CEL program and its source expression.
// The cel.Program is wrapped behind Evaluate / IsValid so the vendor
// type does not leak across the package boundary; consumers read
// Expression directly because it is just a string.
type CompiledPredicate struct {
	program    cel.Program
	Expression CELExpression
}

// scopeVar values for predicateToExpr / ruleToExpr. The empty string
// is the top-level (no scope rebinding); ScopeVarItem is the bound
// name inside any_match / all_match clauses.
const (
	scopeVarTopLevel = ""
	ScopeVarItem     = "__id"
)

// IsValid reports whether the predicate has a non-nil compiled program.
// Use to guard call sites that consume CompiledPredicate values built
// from heterogeneous sources (caches, decoders) where a zero-value
// struct could otherwise reach Eval and panic.
func (cp CompiledPredicate) IsValid() bool {
	return cp.program != nil
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
	expr, err := predicateToExpr(pred, scopeVarTopLevel, 0)
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
	//
	// Thread-safety contract for the cached value: cel.Program (per
	// the cel-go contract documented at
	// https://pkg.go.dev/github.com/google/cel-go/cel#Program) is
	// safe to call Eval on from multiple goroutines after Program()
	// has returned. This compiler caches the *cel.Program directly,
	// so concurrent readers of `cached` can call Eval without
	// further synchronisation. The cache map itself is the only
	// mutable state and is guarded by c.mu.
	ast, issues := c.env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return CompiledPredicate{}, fmt.Errorf("compile CEL expression: %w\n  expression: %s", issues.Err(), expr)
	}

	prg, err := c.env.Program(ast)
	if err != nil {
		return CompiledPredicate{}, fmt.Errorf("program CEL expression: %w", err)
	}

	result := CompiledPredicate{program: prg, Expression: CELExpression(expr)}

	// Double-checked write: another goroutine may have populated the
	// cache while we were compiling. Prefer the existing entry to keep
	// program identity stable for any callers that compared earlier.
	// The duplicate-compile cost on the losing goroutine is bounded by
	// expression count and accepted as cheaper than serialising every
	// compile under the write lock.
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
	return predicateToExpr(pred, "", 0)
}

// maxPredicateDepth caps recursion depth between predicateToExpr and
// ruleToExpr. A pathological YAML (or a future bug that re-enters via
// rule.Any/rule.All cycles) would otherwise blow the stack at compile
// time and surface as a process crash rather than a control-load error.
// 100 is well above any legitimate nesting any human-authored control
// catalog would produce.
const maxPredicateDepth = 100

// predicateToExpr converts an UnsafePredicate to a CEL expression string.
// scopeVar controls field resolution:
//   - "" (empty): top-level — fields like "properties.x" resolve normally
//   - "__id": inside any_match — bare fields like "type" resolve to __id["type"]
//
// depth is the current recursion depth (0 at top level). Callers
// outside this file should use PredicateToExpr.
func predicateToExpr(pred policy.UnsafePredicate, scopeVar string, depth int) (string, error) {
	if depth > maxPredicateDepth {
		return "", fmt.Errorf("predicate nesting exceeds maximum depth (%d) — possible cycle in control YAML", maxPredicateDepth)
	}
	var parts []string

	if len(pred.Any) > 0 {
		anyExprs := make([]string, 0, len(pred.Any))
		for i := range pred.Any {
			e, err := ruleToExpr(&pred.Any[i], scopeVar, depth+1)
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
			e, err := ruleToExpr(&pred.All[i], scopeVar, depth+1)
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

// resolveValueExprFn returns the CEL expression for a rule's right-hand
// side. ValueFromParam wins over the inline value: when a rule sets
// `value_from_param: foo`, the rule reads `params.foo` at evaluation
// time; otherwise the value is encoded as a literal.
func resolveValueExprFn(r *policy.PredicateRule, v any) (string, error) {
	if r.ValueFromParam != "" {
		name := string(r.ValueFromParam)
		if !isSafeParamName(name) {
			return "", fmt.Errorf("value_from_param %q contains characters outside [A-Za-z0-9_.] — would break out of params accessor", name)
		}
		return "params." + name, nil
	}
	return literal(v)
}

// paramNameRe matches the safe character set for value_from_param /
// cross-field-ref names: ASCII letters, digits, underscore, dot. Any
// other character could break out of the `params.<name>` accessor —
// a parenthesis injects a function call, brackets index a different
// scope, whitespace splits the token. Validating once at compile
// time means the runtime evaluator never sees an attacker-controlled
// CEL fragment from a control YAML.
var paramNameRe = regexp.MustCompile(`^[A-Za-z0-9_.]+$`)

func isSafeParamName(s string) bool {
	return s != "" && paramNameRe.MatchString(s)
}

// ruleToExpr converts a single PredicateRule to a CEL expression.
// scopeVar is passed through for field resolution and recursive calls.
func ruleToExpr(r *policy.PredicateRule, scopeVar string, depth int) (string, error) {
	// Handle nested logic blocks (recursive any/all)
	if len(r.Any) > 0 || len(r.All) > 0 {
		nested := policy.UnsafePredicate{Any: r.Any, All: r.All}
		return predicateToExpr(nested, scopeVar, depth+1)
	}

	field := r.Field.String()
	op := r.Op
	val := r.Value.Raw()
	// Empty field name is only valid for the any_identity_match
	// shorthand, which iterates the implicit `identities` list. Every
	// other operator needs a field to resolve against; the earlier
	// shape returned "" and predicateToExpr filtered the empty
	// expression out, silently dropping the rule. A rule that does
	// nothing is a control-authoring defect — surface it at compile
	// time instead of producing an evaluator that never fires.
	if field == "" && op != predicate.OpAnyIdentityMatch {
		return "", errors.New("rule has empty field name")
	}

	// Resolve field access and existence check using current scope.
	// fa/hf are kept as separate locals so existing call sites read
	// naturally; scopedFieldExprs is the structured form used where
	// the pair travels together.
	exprs := scopedFieldExprs(field, scopeVar)
	fa := exprs.access
	hf := exprs.exists

	// resolveValueExpr is the rule-aware right-hand-side resolver:
	// `value_from_param` references emit `params.<name>` so CEL reads
	// the param at evaluation time; plain `value` is treated as a
	// literal. Promoted from inline closure to a free function so the
	// 7+ call sites all bind to the same definition.
	resolveValueExpr := func(v any) (string, error) {
		return resolveValueExprFn(r, v)
	}

	switch op {
	case predicate.OpEq:
		// Fail-OPEN semantics for OpEq: a missing field can never
		// equal anything, so the rule does not fire (`hasField &&
		// field == value`). Equality predicates are typically
		// "this state must hold" assertions where the control
		// fires WHEN the equality holds — an absent field is the
		// "we don't know" state and produces no false-positive
		// violation. Pair with OpPresent if you need to also fail
		// on the absence itself.
		return resolveAndFormatBinary("op eq", "(%s && %s == %s)", val, hf, fa, resolveValueExpr)
	case predicate.OpNe:
		// Fail-CLOSED semantics for OpNe (asymmetric vs OpEq): a
		// missing field is itself the violation
		// (`!hasField || field != value`). Security-critical
		// inequalities (require_tls=true, encryption_enabled=true)
		// interpret an absent field as "the safety property might
		// not hold," which is the reading the control author wanted.
		// The previous fail-open default produced silent-pass on
		// extractor drift.
		//
		// The asymmetry is intentional: OpEq says "match this
		// specific value" (absent field = no match), OpNe says
		// "this value must not be set" (absent field is suspicious
		// because the producer should have emitted it).
		return resolveAndFormatBinary("op ne", "(!(%s) || %s != %s)", val, hf, fa, resolveValueExpr)
	case predicate.OpGt:
		return resolveAndFormatBinary("op gt", "(%s && %s > %s)", val, hf, fa, resolveValueExpr)
	case predicate.OpLt:
		return resolveAndFormatBinary("op lt", "(%s && %s < %s)", val, hf, fa, resolveValueExpr)
	case predicate.OpGte:
		return resolveAndFormatBinary("op gte", "(%s && %s >= %s)", val, hf, fa, resolveValueExpr)
	case predicate.OpLte:
		return resolveAndFormatBinary("op lte", "(%s && %s <= %s)", val, hf, fa, resolveValueExpr)
	case predicate.OpIn:
		return resolveAndFormatBinary("op in", "(%s && %s in %s)", val, hf, fa, resolveValueExpr)
	case predicate.OpContains:
		return resolveAndFormatBinary("op contains", "(%s && string(%s).contains(%s))", val, hf, fa, resolveValueExpr)
	case predicate.OpMissing:
		return ruleToExprMissing(val, hf, fa)
	case predicate.OpPresent:
		return ruleToExprPresent(val, hf, fa)
	case predicate.OpListEmpty:
		return ruleToExprListEmpty(hf, fa), nil
	case predicate.OpNeqField:
		// Cross-field inequality. Both sides must exist for the
		// comparison to be meaningful — a missing target is treated as
		// "safe" (no violation by absence) so the negative operators
		// share a single, predictable convention.
		ofa, ohf := resolveCrossFieldRef(r, val, scopeVar)
		return fmt.Sprintf("(%s && %s && %s != %s)", hf, ohf, fa, ofa), nil
	case predicate.OpNotInField:
		// "source not in target list". Both sides must exist; missing
		// data does not produce a violation. Mirrors OpNeqField.
		ofa, ohf := resolveCrossFieldRef(r, val, scopeVar)
		return fmt.Sprintf("(%s && %s && !(%s in %s))", hf, ohf, fa, ofa), nil
	case predicate.OpNotSubsetOfField:
		// "source list not subset of target list". Both sides must exist;
		// missing data does not produce a violation. Mirrors the other
		// negative cross-field operators.
		ofa, ohf := resolveCrossFieldRef(r, val, scopeVar)
		return fmt.Sprintf("(%s && %s && %s.exists(x, !(x in %s)))", hf, ohf, fa, ofa), nil
	case predicate.OpAnyInField:
		// field.exists(x, x in other) — true when the field (a list)
		// has at least one element that also appears in another list.
		// Both sides must be present; either missing → false.
		// Complement of OpNotSubsetOfField.
		ofa, ohf := resolveCrossFieldRef(r, val, scopeVar)
		return fmt.Sprintf("(%s && %s && %s.exists(x, x in %s))", hf, ohf, fa, ofa), nil
	case predicate.OpAnyMatch:
		return ruleToExprAnyMatch(r, val, scopeVar, false, depth)
	case predicate.OpAnyIdentityMatch:
		// Explicit identity-iteration shorthand. Field can be empty
		// or "identities" — both mean the same thing. The control
		// author writes `op: any_identity_match` so the iteration
		// target is unambiguous, instead of relying on the legacy
		// silent default that any_match used to apply.
		return ruleToExprAnyMatch(r, val, scopeVar, true, depth)
	default:
		return "", fmt.Errorf("unsupported operator: %s", op)
	}
}

// resolveAndFormatBinary is the shared shape for the value-comparison
// operators (OpEq/OpNe/OpGt/OpLt/OpGte/OpLte/OpIn/OpContains): resolve
// the RHS via resolveValueExpr, then format with hf/fa/ve. The
// per-operator template captures both the existence guard and the
// comparison; OpEq/OpNe carry different fail-open / fail-closed
// semantics through their respective templates.
func resolveAndFormatBinary(
	opName, template string,
	val any,
	hf, fa string,
	resolveValueExpr func(any) (string, error),
) (string, error) {
	ve, err := resolveValueExpr(val)
	if err != nil {
		return "", fmt.Errorf("%s: %w", opName, err)
	}
	return fmt.Sprintf(template, hf, fa, ve), nil
}

// ruleToExprMissing handles op:missing. When val is true (the default),
// the rule fires when the field is absent; with val=false, the rule
// fires when the field is present (logical complement).
func ruleToExprMissing(val any, hf, fa string) (string, error) {
	wantMissing, err := coerceBool(val, true)
	if err != nil {
		return "", fmt.Errorf("op missing: %w", err)
	}
	isMissing := fmt.Sprintf("(!(%s) || missing(%s))", hf, fa)
	if !wantMissing {
		return fmt.Sprintf("!(%s)", isMissing), nil
	}
	return isMissing, nil
}

// ruleToExprPresent handles op:present. Mirror of ruleToExprMissing —
// fires on presence by default, complement when val=false.
func ruleToExprPresent(val any, hf, fa string) (string, error) {
	wantPresent, err := coerceBool(val, true)
	if err != nil {
		return "", fmt.Errorf("op present: %w", err)
	}
	isPresent := fmt.Sprintf("(%s && !missing(%s))", hf, fa)
	if !wantPresent {
		return fmt.Sprintf("!(%s)", isPresent), nil
	}
	return isPresent, nil
}

// ruleToExprListEmpty handles op:list_empty.
//
// "empty" semantics:
//
//	field absent          → true  (nothing there to be non-empty)
//	collection size == 0  → true  (list/map/string with no elements)
//	not a collection type → true  (an int / bool / number can't
//	                               hold a list-shaped value, so
//	                               it's logically empty for the
//	                               purpose of this operator)
//
// size() errors on non-collection types, so the type guard must
// short-circuit before size() runs. CEL does not allow
// `string(type(x))` for a dyn-typed value, so the test is expressed
// as direct type-token equality. Each `type(literal)` resolves to a
// singleton type value at compile time, so the per-evaluation cost
// is just three pointer comparisons. The short-circuit chain is:
//  1. field absent              → true
//  2. type not list/map/string  → true
//  3. size() == 0               → true
//
// Non-empty collections fall through to false (= violation).
func ruleToExprListEmpty(hf, fa string) string {
	return fmt.Sprintf(
		"(!(%s) || !(type(%s) == type([]) || type(%s) == type({}) || type(%s) == type(\"\")) || size(%s) == 0)",
		hf, fa, fa, fa, fa,
	)
}

// resolveCrossFieldRef returns (accessExpr, existsExpr) for the right-hand
// side of a cross-field operator. A rule may target either:
//   - a sibling field on the same asset (`value: properties.foo` or any
//     other dotted path resolved via the active scope), or
//   - a control parameter (`value_from_param: bar`).
//
// `params` is always present in the activation, so the existence guard for
// a param ref is the literal `true` — the param itself is required to be
// declared in the control's `params:` block, so absence at evaluation time
// would be a control-load defect, not a data-shape question.
func resolveCrossFieldRef(r *policy.PredicateRule, val any, scopeVar string) (access string, exists string) {
	if r.ValueFromParam != "" {
		name := string(r.ValueFromParam)
		if !isSafeParamName(name) {
			// Compile-time fail-loud: emit an expression that
			// evaluates to a clearly-broken false rather than
			// concatenating an attacker-controlled string. The
			// upstream Compile() returns an error from the literal
			// CEL parse failure, which surfaces the bad control
			// YAML at load time.
			return "params.__INVALID_PARAM_NAME__", "false"
		}
		return "params." + name, "true"
	}
	other := fmt.Sprint(val)
	return scopedFieldAccess(other, scopeVar), scopedHasField(other, scopeVar)
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
func ruleToExprAnyMatch(r *policy.PredicateRule, val any, outerScope string, identityShorthand bool, depth int) (string, error) {
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
	// Forward depth+1 so any_match / any_identity_match comprehensions
	// count toward the maxPredicateDepth cap. The earlier shape
	// hardcoded depth=1 here, which let a chain of nested any_match
	// rules bypass the cap and reach unbounded recursion — a stack-
	// overflow vector at compile time.
	innerExpr, err := predicateToExpr(*nested, ScopeVarItem, depth+1)
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
