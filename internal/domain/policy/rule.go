package policy

import (
	"sort"
	"strings"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/predicate"
)

// PredicateRule is a single predicate condition or nested predicate.
type PredicateRule struct {
	// Simple field comparison
	Field          string             `yaml:"field,omitempty"`
	Op             predicate.Operator `yaml:"op,omitempty"`
	Value          any                `yaml:"value,omitempty"`
	ValueFromParam string             `yaml:"value_from_param,omitempty"` // resolve value from params

	// Nested predicates
	Any []PredicateRule `yaml:"any,omitempty"`
	All []PredicateRule `yaml:"all,omitempty"`

	// Cached parsed field path to avoid repeated split allocations on hot evaluation paths.
	fieldParts      []string `yaml:"-"`
	fieldPartsReady bool     `yaml:"-"`
}

type complexOperatorEval struct {
	ctx          EvalContext
	fieldExists  bool
	fieldValue   any
	compareValue any
}

// Matches checks if a single predicate rule matches the asset without params.
func (pr *PredicateRule) Matches(r asset.Asset) bool {
	ctx := NewAssetEvalContext(r, nil)
	return pr.MatchesWithContext(ctx)
}

// MatchesWithContext checks if a predicate rule matches with full context.
func (pr *PredicateRule) MatchesWithContext(ctx EvalContext) bool {
	// Handle nested "any" predicate
	if len(pr.Any) > 0 {
		return pr.anyMatches(ctx)
	}

	// Handle nested "all" predicate
	if len(pr.All) > 0 {
		return pr.allMatch(ctx)
	}

	// Simple field comparison
	fieldValue, fieldExists := getFieldValueWithParts(ctx, pr.parsedFieldParts())

	// Resolve comparison value (from value or value_from_param)
	compareValue := pr.Value
	if pr.ValueFromParam != "" {
		paramValue, ok := ctx.Param(pr.ValueFromParam)
		if !ok || paramValue == nil {
			return false
		}
		compareValue = paramValue
	}

	if result, handled := predicate.EvaluateOperator(pr.Op, fieldExists, fieldValue, compareValue); handled {
		return result
	}

	return pr.evaluateComplexOperator(complexOperatorEval{
		ctx:          ctx,
		fieldExists:  fieldExists,
		fieldValue:   fieldValue,
		compareValue: compareValue,
	})
}

func (pr *PredicateRule) evaluateComplexOperator(eval complexOperatorEval) bool {
	switch pr.Op {
	case predicate.OpNotSubsetOfField:
		return evaluateNotSubsetOfField(eval)
	case predicate.OpNeqField:
		return evaluateNeqField(eval)
	case predicate.OpNotInField:
		return evaluateNotInField(eval)
	case predicate.OpAnyMatch:
		return evaluateAnyMatch(eval)
	default:
		return false
	}
}

func evaluateNotSubsetOfField(eval complexOperatorEval) bool {
	if !eval.fieldExists {
		return false
	}
	otherValue, otherExists, ok := resolveComparedField(eval.ctx, eval.compareValue)
	if !ok {
		return false
	}
	if !otherExists {
		return true
	}
	return predicate.ListHasElementsNotIn(eval.fieldValue, otherValue)
}

func evaluateNeqField(eval complexOperatorEval) bool {
	if !eval.fieldExists {
		return false
	}
	otherValue, otherExists, ok := resolveComparedField(eval.ctx, eval.compareValue)
	if !ok {
		return false
	}
	if !otherExists {
		return true
	}
	return !predicate.EqualValues(eval.fieldValue, otherValue)
}

func evaluateNotInField(eval complexOperatorEval) bool {
	if !eval.fieldExists {
		return true
	}
	otherValue, otherExists, ok := resolveComparedField(eval.ctx, eval.compareValue)
	if !ok || !otherExists {
		return true
	}
	return !predicate.ValueInList(eval.fieldValue, otherValue)
}

func evaluateAnyMatch(eval complexOperatorEval) bool {
	if !eval.fieldExists {
		return false
	}
	identities, ok := eval.fieldValue.([]asset.CloudIdentity)
	if !ok {
		return false
	}
	nestedPred, err := eval.ctx.ParsePredicate(eval.compareValue)
	if nestedPred == nil || err != nil {
		return false
	}
	idCtx := EvalContext{
		Params:          eval.ctx.Params,
		PredicateParser: eval.ctx.PredicateParser,
	}
	for i := range identities {
		idCtx.Properties = identities[i].Map()
		if nestedPred.EvaluateWithContext(idCtx) {
			return true
		}
	}
	return false
}

func resolveComparedField(ctx EvalContext, compareValue any) (any, bool, bool) {
	otherFieldPath, ok := compareValue.(string)
	if !ok {
		return nil, false, false
	}
	otherValue, otherExists := getFieldValueWithContext(ctx, otherFieldPath)
	return otherValue, otherExists, true
}

func (pr *PredicateRule) anyMatches(ctx EvalContext) bool {
	for i := range pr.Any {
		if pr.Any[i].MatchesWithContext(ctx) {
			return true
		}
	}
	return false
}

func (pr *PredicateRule) allMatch(ctx EvalContext) bool {
	for i := range pr.All {
		if !pr.All[i].MatchesWithContext(ctx) {
			return false
		}
	}
	return len(pr.All) > 0
}

func (pr *PredicateRule) parsedFieldParts() []string {
	if pr.fieldPartsReady {
		return pr.fieldParts
	}
	if pr.Field == "" {
		pr.fieldParts = nil
		pr.fieldPartsReady = true
		return nil
	}
	pr.fieldParts = strings.Split(pr.Field, ".")
	pr.fieldPartsReady = true
	return pr.fieldParts
}

// ExtractMisconfigurations extracts misconfiguration data from the predicate tree.
// Returns a slice sorted by Property for deterministic output.
func ExtractMisconfigurations(p *UnsafePredicate, props map[string]any) []Misconfiguration {
	if p == nil {
		return nil
	}
	var result []Misconfiguration
	for i := range p.Any {
		p.Any[i].extractMisconfigurationFields(props, &result)
	}
	for i := range p.All {
		p.All[i].extractMisconfigurationFields(props, &result)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Property < result[j].Property
	})
	return result
}

// extractMisconfigurationFields extracts misconfiguration data from a single predicate rule.
func (r *PredicateRule) extractMisconfigurationFields(props map[string]any, result *[]Misconfiguration) {
	// Handle nested predicates
	if len(r.Any) > 0 || len(r.All) > 0 {
		for i := range r.Any {
			r.Any[i].extractMisconfigurationFields(props, result)
		}
		for i := range r.All {
			r.All[i].extractMisconfigurationFields(props, result)
		}
		return
	}

	if r.Field == "" {
		return
	}
	fieldPath := strings.TrimPrefix(r.Field, fieldNamespaceProperties+".")
	val, _ := nestedPropertyValue(props, fieldPath)
	*result = append(*result, Misconfiguration{
		Property:    fieldPath,
		ActualValue: val,
		Operator:    PredicateOperator(r.Op),
		UnsafeValue: r.Value,
	})
}

func nestedPropertyValue(props map[string]any, path string) (any, bool) {
	parts := splitPath(path)
	var current any = props
	for _, part := range parts {
		if m, ok := current.(map[string]any); ok {
			v, exists := m[part]
			if !exists {
				return nil, false
			}
			current = v
		} else {
			return nil, false
		}
	}
	return current, true
}

func splitPath(path string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(path); i++ {
		if path[i] == '.' {
			if i > start {
				parts = append(parts, path[start:i])
			}
			start = i + 1
		}
	}
	if start < len(path) {
		parts = append(parts, path[start:])
	}
	return parts
}
