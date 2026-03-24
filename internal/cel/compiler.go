package cel

import (
	"fmt"
	"strings"
	"sync"

	"github.com/google/cel-go/cel"

	"github.com/sufield/stave/pkg/alpha/domain/policy"
	"github.com/sufield/stave/pkg/alpha/domain/predicate"
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
		return "false", nil
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
	// as CEL field accesses instead of string literals.
	resolveValueExpr := func(v any) string {
		if s, ok := v.(string); ok && strings.HasPrefix(s, "params.") {
			return s // emit as-is — CEL resolves params.X from the activation map
		}
		return literal(v)
	}

	switch op {
	case predicate.OpEq:
		return fmt.Sprintf("(%s && %s == %s)", hf, fa, resolveValueExpr(val)), nil
	case predicate.OpNe:
		return fmt.Sprintf("(!(%s) || %s != %s)", hf, fa, resolveValueExpr(val)), nil
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
		isMissing := fmt.Sprintf("(!(%s) || missing(%s))", hf, fa)
		if wantMissing, ok := val.(bool); ok && !wantMissing {
			return fmt.Sprintf("!(%s)", isMissing), nil
		}
		return isMissing, nil
	case predicate.OpPresent:
		isPresent := fmt.Sprintf("(%s && !missing(%s))", hf, fa)
		if wantPresent, ok := val.(bool); ok && !wantPresent {
			return fmt.Sprintf("!(%s)", isPresent), nil
		}
		return isPresent, nil
	case predicate.OpListEmpty:
		return fmt.Sprintf("(!(%s) || size(%s) == 0)", hf, fa), nil
	case predicate.OpNeqField:
		other := fmt.Sprint(val)
		ofa := scopedFieldAccess(other, scopeVar)
		ohf := scopedHasField(other, scopeVar)
		return fmt.Sprintf("(%s && (!(%s) || %s != %s))", hf, ohf, fa, ofa), nil
	case predicate.OpNotInField:
		other := fmt.Sprint(val)
		ofa := scopedFieldAccess(other, scopeVar)
		ohf := scopedHasField(other, scopeVar)
		return fmt.Sprintf("(!(%s) || !(%s) || !(%s in %s))", hf, ohf, fa, ofa), nil
	case predicate.OpNotSubsetOfField:
		other := fmt.Sprint(val)
		ofa := scopedFieldAccess(other, scopeVar)
		ohf := scopedHasField(other, scopeVar)
		return fmt.Sprintf("(%s && %s.exists(x, !(%s) || !(x in %s)))", hf, fa, ohf, ofa), nil
	case predicate.OpAnyMatch:
		return ruleToExprAnyMatch(r, val)
	default:
		return "", fmt.Errorf("unsupported operator: %s", op)
	}
}

// ruleToExprAnyMatch compiles an any_match rule into a CEL exists() macro.
// The nested predicate is compiled with "__id" scope so field references
// resolve against the iterator variable.
func ruleToExprAnyMatch(_ *policy.PredicateRule, val any) (string, error) {
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
			return "", fmt.Errorf("any_match: nil nested predicate")
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
		return "", fmt.Errorf("any_match: empty nested predicate")
	}

	return fmt.Sprintf("identities.exists(__id, %s)", innerExpr), nil
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
