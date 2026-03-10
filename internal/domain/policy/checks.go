package policy

import (
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/diag"
	"github.com/sufield/stave/internal/pkg/fp"
)

// FindMissingParamReferences checks if predicates reference params that don't exist.
func FindMissingParamReferences(pred UnsafePredicate, params ControlParams) []string {
	missingSet := make(map[string]struct{})
	walkPredicateRules(pred, func(rule PredicateRule) {
		addMissingParamReference(rule.ValueFromParam, params, missingSet)
	})

	return fp.SortedKeys(missingSet)
}

func addMissingParamReference(param string, params ControlParams, missingSet map[string]struct{}) {
	if param == "" {
		return
	}
	if _, exists := params[param]; exists {
		return
	}
	missingSet[param] = struct{}{}
}

// CheckControlEffectiveness checks if controls match any assets.
func CheckControlEffectiveness(controls []ControlDefinition, snapshots []asset.Snapshot) []diag.Issue {
	var issues []diag.Issue

	for _, ctl := range controls {
		if !controlMatchesAnyAsset(ctl, snapshots) {
			issues = append(issues, diag.New(diag.CodeControlNeverMatches).
				Warning().
				Action("This may be expected if all resources are safe, or check predicate rules").
				WithMap(controlCtx(&ctl, nil)).
				Build())
		}
	}

	return issues
}

func controlMatchesAnyAsset(ctl ControlDefinition, snapshots []asset.Snapshot) bool {
	for _, snap := range snapshots {
		for _, a := range snap.Assets {
			if ctl.UnsafePredicate.Evaluate(a, ctl.Params) {
				return true
			}
		}
	}
	return false
}

func walkPredicateRules(pred UnsafePredicate, visit func(PredicateRule)) {
	for _, rule := range pred.Any {
		walkPredicateRule(rule, visit)
	}
	for _, rule := range pred.All {
		walkPredicateRule(rule, visit)
	}
}

func walkPredicateRule(rule PredicateRule, visit func(PredicateRule)) {
	visit(rule)
	for _, nested := range rule.Any {
		walkPredicateRule(nested, visit)
	}
	for _, nested := range rule.All {
		walkPredicateRule(nested, visit)
	}
}
