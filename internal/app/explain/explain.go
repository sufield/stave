// Package explain provides control explanation and documentation lookup.
package explain

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/app/contracts"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
)

// ControlFinder loads a single control by ID.
type ControlFinder interface {
	FindByID(ctx context.Context, dir string, id kernel.ControlID) (policy.ControlDefinition, error)
}

// Input holds the inputs for the explain workflow.
type Input struct {
	ControlID   kernel.ControlID
	ControlsDir string
}

// Explainer analyzes a control and explains its predicate structure.
type Explainer struct {
	Finder ControlFinder
}

// Run executes the explain workflow.
func (e *Explainer) Run(ctx context.Context, input Input) (contracts.ExplainResult, error) {
	if input.ControlID == "" {
		return contracts.ExplainResult{}, errors.New("control id cannot be empty")
	}
	controlsDir := strings.TrimSpace(input.ControlsDir)
	ctl, err := e.Finder.FindByID(ctx, controlsDir, input.ControlID)
	if err != nil {
		return contracts.ExplainResult{}, fmt.Errorf("find by i d: %w", err)
	}
	return analyze(ctl), nil
}

func analyze(ctl policy.ControlDefinition) contracts.ExplainResult {
	fields, rules := walkPredicate(ctl.UnsafePredicate, ctl.Params)
	slices.Sort(fields)
	return contracts.ExplainResult{
		ControlID:          ctl.ID.String(),
		Name:               ctl.Name,
		Description:        ctl.Description,
		Type:               ctl.Type.String(),
		MatchedFields:      fields,
		Rules:              rules,
		MinimalObservation: buildMinimalObservation(fields, rules),
	}
}

func walkPredicate(pred policy.UnsafePredicate, params policy.ControlParams) ([]string, []contracts.ExplainRule) {
	rules, fieldSet := walkRules("any", pred.Any, params)
	allRules, allFields := walkRules("all", pred.All, params)
	rules = append(rules, allRules...)
	for f := range allFields {
		fieldSet[f] = struct{}{}
	}

	fields := make([]string, 0, len(fieldSet))
	for f := range fieldSet {
		fields = append(fields, f)
	}
	slices.Sort(fields)
	return fields, rules
}

func walkRules(from string, prs []policy.PredicateRule, params policy.ControlParams) ([]contracts.ExplainRule, map[string]struct{}) {
	var rules []contracts.ExplainRule
	fieldSet := map[string]struct{}{}
	for i := range prs {
		r := prs[i]
		loc := fmt.Sprintf("%s[%d]", from, i)
		if len(r.Any) > 0 {
			sub, nf := walkRules(loc+".any", r.Any, params)
			rules = append(rules, sub...)
			for f := range nf {
				fieldSet[f] = struct{}{}
			}
		}
		if len(r.All) > 0 {
			sub, nf := walkRules(loc+".all", r.All, params)
			rules = append(rules, sub...)
			for f := range nf {
				fieldSet[f] = struct{}{}
			}
		}
		if r.Field.IsZero() {
			continue
		}
		value, comment := resolveRuleValue(r, params)
		rules = append(rules, contracts.ExplainRule{
			Path:    r.Field.String(),
			Op:      r.Op,
			Value:   value,
			From:    loc,
			Comment: comment,
		})
		fieldSet[r.Field.String()] = struct{}{}
	}
	return rules, fieldSet
}

func resolveRuleValue(r policy.PredicateRule, params policy.ControlParams) (value any, comment string) {
	// Hierarchy: parameter resolution OVERRIDES the literal value.
	// Start from the literal as a recoverable fallback so a
	// parameter-lookup failure (config drift, typo in a control
	// YAML) still produces explainable output. The earlier shape
	// silently swallowed the error, masking the drift.
	literalValue := r.Value.Raw()
	value = literalValue

	if !r.ValueFromParam.IsZero() && !params.IsZero() {
		paramName := r.ValueFromParam.String()
		resolved, paramFound := params.Get(paramName)
		if !paramFound {
			slog.Warn("explain: fallback to literal; param not present in control",
				"param", paramName)
		} else {
			value = resolved
		}
	}
	if !r.ValueFromParam.IsZero() {
		comment = "value resolved from params." + r.ValueFromParam.String()
	}
	return value, comment
}

func buildMinimalObservation(fields []string, rules []contracts.ExplainRule) map[string]any {
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

func sampleValue(r contracts.ExplainRule) any {
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
			// Existing non-map value at an intermediate path segment
			// gets clobbered. Surface a warning so a caller that
			// tried to set both `a.b` (string) and `a.b.c` (any) sees
			// the data loss instead of silently losing the leaf
			// value. The existing value is still overwritten — the
			// alternative (refusing to set `a.b.c`) would silently
			// drop the new value, which is an equally bad failure
			// mode but harder to detect.
			if existing, present := curr[p]; present {
				slog.Warn("explain.setNested: overwriting non-map intermediate value",
					"path", dotted, "segment", p,
					"existing_type", fmt.Sprintf("%T", existing))
			}
			next = map[string]any{}
			curr[p] = next
		}
		curr = next
	}
}
