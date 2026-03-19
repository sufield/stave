package cel

import (
	"fmt"
	"strings"
	"sync"

	"github.com/google/cel-go/cel"

	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/domain/predicate"
)

// CompiledPredicate holds a compiled CEL program and its source expression.
type CompiledPredicate struct {
	Program    cel.Program
	Expression string
}

// Compiler translates UnsafePredicate structures into compiled CEL programs.
// Compiled programs are cached by expression string for thread-safe reuse.
type Compiler struct {
	env   *cel.Env
	mu    sync.RWMutex
	cache map[string]CompiledPredicate

	// PredicateParser converts a raw map[string]any (from YAML unmarshal)
	// into a typed UnsafePredicate. Required for any_match operator support.
	// Callers should set this to the adapter-layer ParsePredicate function.
	PredicateParser func(v any) (*policy.UnsafePredicate, error)
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
	expr := predicateToExpr(pred, "")
	if expr == "" {
		return CompiledPredicate{}, fmt.Errorf("predicate produced empty expression")
	}

	// Check cache
	c.mu.RLock()
	if cached, ok := c.cache[expr]; ok {
		c.mu.RUnlock()
		return cached, nil
	}
	c.mu.RUnlock()

	// Compile
	ast, issues := c.env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return CompiledPredicate{}, fmt.Errorf("compile CEL expression: %w\n  expression: %s", issues.Err(), expr)
	}

	prg, err := c.env.Program(ast)
	if err != nil {
		return CompiledPredicate{}, fmt.Errorf("program CEL expression: %w", err)
	}

	result := CompiledPredicate{Program: prg, Expression: expr}

	// Cache
	c.mu.Lock()
	c.cache[expr] = result
	c.mu.Unlock()

	return result, nil
}

// PredicateToExpr converts an UnsafePredicate to a CEL expression string.
// Exported for testing; callers should use Compile instead.
func PredicateToExpr(pred policy.UnsafePredicate) string {
	return predicateToExpr(pred, "")
}

// predicateToExpr converts an UnsafePredicate to a CEL expression string.
// scopeVar controls field resolution:
//   - "" (empty): top-level — fields like "properties.x" resolve normally
//   - "__id": inside any_match — bare fields like "type" resolve to __id["type"]
func predicateToExpr(pred policy.UnsafePredicate, scopeVar string) string {
	var parts []string

	if len(pred.Any) > 0 {
		anyExprs := make([]string, 0, len(pred.Any))
		for i := range pred.Any {
			if e := ruleToExpr(&pred.Any[i], scopeVar); e != "" {
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
			if e := ruleToExpr(&pred.All[i], scopeVar); e != "" {
				allExprs = append(allExprs, e)
			}
		}
		if len(allExprs) > 0 {
			parts = append(parts, "("+strings.Join(allExprs, " && ")+")")
		}
	}

	if len(parts) == 0 {
		return "false"
	}
	return strings.Join(parts, " && ")
}

// ruleToExpr converts a single PredicateRule to a CEL expression.
// scopeVar is passed through for field resolution and recursive calls.
func ruleToExpr(r *policy.PredicateRule, scopeVar string) string {
	// Handle nested logic blocks (recursive any/all)
	if len(r.Any) > 0 || len(r.All) > 0 {
		nested := policy.UnsafePredicate{Any: r.Any, All: r.All}
		return predicateToExpr(nested, scopeVar)
	}

	field := r.Field.String()
	if field == "" {
		return ""
	}

	op := r.Op
	val := r.Value.Raw()

	// Resolve field access and existence check using current scope
	fa := scopedFieldAccess(field, scopeVar)
	hf := scopedHasField(field, scopeVar)

	switch op {
	case predicate.OpEq:
		return fmt.Sprintf("(%s && %s == %s)", hf, fa, literal(val))
	case predicate.OpNe:
		return fmt.Sprintf("(!(%s) || %s != %s)", hf, fa, literal(val))
	case predicate.OpGt:
		return fmt.Sprintf("(%s && %s > %s)", hf, fa, literal(val))
	case predicate.OpLt:
		return fmt.Sprintf("(%s && %s < %s)", hf, fa, literal(val))
	case predicate.OpGte:
		return fmt.Sprintf("(%s && %s >= %s)", hf, fa, literal(val))
	case predicate.OpLte:
		return fmt.Sprintf("(%s && %s <= %s)", hf, fa, literal(val))
	case predicate.OpIn:
		return fmt.Sprintf("(%s && %s in %s)", hf, fa, literal(val))
	case predicate.OpContains:
		return fmt.Sprintf("(%s && string(%s).contains(%s))", hf, fa, literal(val))
	case predicate.OpMissing:
		isMissing := fmt.Sprintf("(!(%s) || missing(%s))", hf, fa)
		if wantMissing, ok := val.(bool); ok && !wantMissing {
			return fmt.Sprintf("!(%s)", isMissing)
		}
		return isMissing
	case predicate.OpPresent:
		isPresent := fmt.Sprintf("(%s && !missing(%s))", hf, fa)
		if wantPresent, ok := val.(bool); ok && !wantPresent {
			return fmt.Sprintf("!(%s)", isPresent)
		}
		return isPresent
	case predicate.OpListEmpty:
		return fmt.Sprintf("(!(%s) || size(%s) == 0)", hf, fa)
	case predicate.OpNeqField:
		other := fmt.Sprint(val)
		ofa := scopedFieldAccess(other, scopeVar)
		ohf := scopedHasField(other, scopeVar)
		return fmt.Sprintf("(%s && (!(%s) || %s != %s))", hf, ohf, fa, ofa)
	case predicate.OpNotInField:
		other := fmt.Sprint(val)
		ofa := scopedFieldAccess(other, scopeVar)
		ohf := scopedHasField(other, scopeVar)
		return fmt.Sprintf("(!(%s) || !(%s) || !(%s in %s))", hf, ohf, fa, ofa)
	case predicate.OpNotSubsetOfField:
		other := fmt.Sprint(val)
		ofa := scopedFieldAccess(other, scopeVar)
		ohf := scopedHasField(other, scopeVar)
		return fmt.Sprintf("(%s && %s.exists(x, !(%s) || !(x in %s)))", hf, fa, ohf, ofa)
	case predicate.OpAnyMatch:
		return ruleToExprAnyMatch(r, val)
	default:
		return "false /* unsupported operator: " + string(op) + " */"
	}
}

// ruleToExprAnyMatch compiles an any_match rule into a CEL exists() macro.
// The nested predicate is compiled with "__id" scope so field references
// resolve against the iterator variable.
func ruleToExprAnyMatch(_ *policy.PredicateRule, val any) string {
	// The value must be a nested predicate structure (map[string]any from YAML).
	// Convert it to an UnsafePredicate using YAML round-trip.
	nested, err := parseNestedPredicate(val)
	if err != nil || nested == nil {
		return "false /* any_match: failed to parse nested predicate */"
	}

	// Compile the nested predicate with "__id" scope — field references
	// like "type", "id", "purpose" will resolve to __id["type"], etc.
	innerExpr := predicateToExpr(*nested, "__id")
	if innerExpr == "" || innerExpr == "false" {
		return "false /* any_match: empty nested predicate */"
	}

	return fmt.Sprintf("identities.exists(__id, %s)", innerExpr)
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
func literal(v any) string {
	switch val := v.(type) {
	case bool:
		if val {
			return "true"
		}
		return "false"
	case string:
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
