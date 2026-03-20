package policy

import (
	"slices"

	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/diag"
)

// FindMissingParamReferences identifies predicate rules that reference control
// parameters that have not been defined.
func FindMissingParamReferences(pred UnsafePredicate, params ControlParams) []string {
	missingSet := make(map[string]struct{})

	pred.Walk(func(rule PredicateRule) {
		if rule.ValueFromParam.IsZero() {
			return
		}
		key := rule.ValueFromParam.String()
		if !params.HasKey(key) {
			missingSet[key] = struct{}{}
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
func CheckControlEffectiveness(controls []ControlDefinition, snapshots []asset.Snapshot, eval PredicateEval) []diag.Issue {
	var issues []diag.Issue

	for _, ctl := range controls {
		if !isControlMatchingAny(ctl, snapshots, eval) {
			issues = append(issues, diag.New(diag.CodeControlNeverMatches).
				Warning().
				Action("Check predicate field paths or verify if all resources are currently safe.").
				WithMap(buildCtx(&ctl, nil)).
				Build())
		}
	}

	return issues
}

func isControlMatchingAny(ctl ControlDefinition, snapshots []asset.Snapshot, eval PredicateEval) bool {
	if eval == nil {
		return false
	}
	for _, snap := range snapshots {
		for _, a := range snap.Assets {
			unsafe, err := eval(ctl, a, snap.Identities)
			if err == nil && unsafe {
				return true
			}
		}
	}
	return false
}

// --- Recursive Traversal Methods ---

// Walk performs a depth-first traversal of all rules within the predicate.
func (p UnsafePredicate) Walk(visit func(PredicateRule)) {
	for _, r := range p.Any {
		r.Walk(visit)
	}
	for _, r := range p.All {
		r.Walk(visit)
	}
}

// Walk visits the current rule and recursively visits all child rules.
func (r PredicateRule) Walk(visit func(PredicateRule)) {
	visit(r)
	for _, child := range r.Any {
		child.Walk(visit)
	}
	for _, child := range r.All {
		child.Walk(visit)
	}
}
