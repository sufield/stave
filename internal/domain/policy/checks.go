package policy

import (
	"slices"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/diag"
)

// FindMissingParamReferences identifies predicate rules that reference control
// parameters that have not been defined.
func FindMissingParamReferences(pred UnsafePredicate, params ControlParams) []string {
	missingSet := make(map[string]struct{})

	pred.walk(func(rule PredicateRule) {
		p := rule.ValueFromParam
		if p == "" {
			return
		}
		if _, exists := params[p]; !exists {
			missingSet[p] = struct{}{}
		}
	})

	if len(missingSet) == 0 {
		return nil
	}

	keys := make([]string, 0, len(missingSet))
	for k := range missingSet {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// CheckControlEffectiveness evaluates if controls are matching any assets in the
// current dataset. This helps identify misconfigured predicates.
func CheckControlEffectiveness(controls []ControlDefinition, snapshots []asset.Snapshot) []diag.Issue {
	var issues []diag.Issue

	for _, ctl := range controls {
		if !isControlMatchingAny(ctl, snapshots) {
			issues = append(issues, diag.New(diag.CodeControlNeverMatches).
				Warning().
				Action("Check predicate field paths or verify if all resources are currently safe.").
				WithMap(buildCtx(&ctl, nil)).
				Build())
		}
	}

	return issues
}

func isControlMatchingAny(ctl ControlDefinition, snapshots []asset.Snapshot) bool {
	for _, snap := range snapshots {
		for _, a := range snap.Assets {
			if ctl.UnsafePredicate.Evaluate(a, ctl.Params) {
				return true
			}
		}
	}
	return false
}

// --- Recursive Traversal Methods ---

// walk performs a depth-first traversal of all rules within the predicate.
func (p UnsafePredicate) walk(visit func(PredicateRule)) {
	for _, r := range p.Any {
		r.walk(visit)
	}
	for _, r := range p.All {
		r.walk(visit)
	}
}

// walk visits the current rule and recursively visits all child rules.
func (r PredicateRule) walk(visit func(PredicateRule)) {
	visit(r)
	for _, child := range r.Any {
		child.walk(visit)
	}
	for _, child := range r.All {
		child.walk(visit)
	}
}
