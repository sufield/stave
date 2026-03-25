package explain

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
	"github.com/sufield/stave/pkg/alpha/domain/predicate"
)

// ExplainResult is an alias for contracts.ExplainResult.
type ExplainResult = contracts.ExplainResult

// ExplainRule is an alias for contracts.ExplainRule.
type ExplainRule = contracts.ExplainRule

// ControlFinder loads a single control by ID.
type ControlFinder interface {
	FindByID(ctx context.Context, dir string, id kernel.ControlID) (policy.ControlDefinition, error)
}

// ExplainInput holds the inputs for the explain workflow.
type ExplainInput struct {
	ControlID   kernel.ControlID
	ControlsDir string
}

// Explainer analyzes a control and explains its predicate structure.
type Explainer struct {
	Finder ControlFinder
}

// Run executes the explain workflow.
func (e *Explainer) Run(ctx context.Context, input ExplainInput) (ExplainResult, error) {
	if input.ControlID == "" {
		return ExplainResult{}, fmt.Errorf("control id cannot be empty")
	}
	controlsDir := strings.TrimSpace(input.ControlsDir)
	ctl, err := e.Finder.FindByID(ctx, controlsDir, input.ControlID)
	if err != nil {
		return ExplainResult{}, err
	}
	return analyze(ctl), nil
}

func analyze(ctl policy.ControlDefinition) ExplainResult {
	fields, rules := walkPredicate(ctl.UnsafePredicate, ctl.Params)
	slices.Sort(fields)
	return ExplainResult{
		ControlID:          ctl.ID.String(),
		Name:               ctl.Name,
		Description:        ctl.Description,
		Type:               ctl.Type.String(),
		MatchedFields:      fields,
		Rules:              rules,
		MinimalObservation: buildMinimalObservation(fields, rules),
	}
}

func walkPredicate(pred policy.UnsafePredicate, params policy.ControlParams) ([]string, []ExplainRule) {
	rules, fieldSet := walkRules("any", pred.Any, params)
	allRules, allFields := walkRules("all", pred.All, params)
	rules = append(rules, allRules...)
	for f := range allFields {
		fieldSet[f] = true
	}

	fields := make([]string, 0, len(fieldSet))
	for f := range fieldSet {
		fields = append(fields, f)
	}
	slices.Sort(fields)
	return fields, rules
}

func walkRules(from string, prs []policy.PredicateRule, params policy.ControlParams) ([]ExplainRule, map[string]bool) {
	var rules []ExplainRule
	fieldSet := map[string]bool{}
	for i := range prs {
		r := prs[i]
		loc := fmt.Sprintf("%s[%d]", from, i)
		if len(r.Any) > 0 {
			sub, nf := walkRules(loc+".any", r.Any, params)
			rules = append(rules, sub...)
			for f := range nf {
				fieldSet[f] = true
			}
		}
		if len(r.All) > 0 {
			sub, nf := walkRules(loc+".all", r.All, params)
			rules = append(rules, sub...)
			for f := range nf {
				fieldSet[f] = true
			}
		}
		if r.Field.IsZero() {
			continue
		}
		value, comment := resolveRuleValue(r, params)
		rules = append(rules, ExplainRule{
			Path:    r.Field.String(),
			Op:      r.Op,
			Value:   value,
			From:    loc,
			Comment: comment,
		})
		fieldSet[r.Field.String()] = true
	}
	return rules, fieldSet
}

func resolveRuleValue(r policy.PredicateRule, params policy.ControlParams) (value any, comment string) {
	value = r.Value.Raw()
	if !r.ValueFromParam.IsZero() && !params.IsZero() {
		value, _ = params.Get(r.ValueFromParam.String())
	}
	if !r.ValueFromParam.IsZero() {
		comment = "value resolved from params." + r.ValueFromParam.String()
	}
	return value, comment
}

func buildMinimalObservation(fields []string, rules []ExplainRule) map[string]any {
	props := map[string]any{}
	valueByPath := map[string]any{}
	for _, r := range rules {
		if r.Path == "" {
			continue
		}
		valueByPath[r.Path] = sampleValue(r)
	}

	for _, fullPath := range fields {
		trimmed := strings.TrimPrefix(fullPath, "properties.")
		if trimmed == "" || trimmed == fullPath && strings.HasPrefix(fullPath, "properties.") {
			continue
		}
		setNested(props, trimmed, valueByPath[fullPath])
	}

	return map[string]any{
		"schema_version": string(kernel.SchemaObservation),
		"generated_by": map[string]any{
			"source_type": "aws-s3-snapshot",
			"tool":        "stave-explain",
		},
		"captured_at": "2026-01-18T00:00:00Z",
		"assets": []map[string]any{
			{
				"id":         "example-asset",
				"type":       "aws_s3_bucket",
				"vendor":     "aws",
				"properties": props,
			},
		},
	}
}

func sampleValue(r ExplainRule) any {
	if r.Op == predicate.OpMissing {
		return nil
	}
	if r.Value != nil {
		return r.Value
	}
	switch r.Op {
	case predicate.OpEq, predicate.OpNe:
		return false
	case predicate.OpContains, predicate.OpIn:
		return "example"
	case predicate.OpPresent:
		return "example"
	default:
		return "example"
	}
}

func setNested(root map[string]any, dotted string, val any) {
	if dotted == "" {
		return
	}
	parts := strings.Split(dotted, ".")
	curr := root
	for i, p := range parts {
		if i == len(parts)-1 {
			if val != nil {
				curr[p] = val
			}
			return
		}
		next, ok := curr[p].(map[string]any)
		if !ok {
			next = map[string]any{}
			curr[p] = next
		}
		curr = next
	}
}
