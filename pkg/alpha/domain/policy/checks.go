package policy

import (
	"slices"

	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/diag"
)

// MissingParamReferences identifies parameter names used in rules but
// missing from the control's params definition. Returns a sorted,
// deduplicated list of missing keys.
func (p UnsafePredicate) MissingParamReferences(params ControlParams) []string {
	missingSet := make(map[string]struct{})

	p.Walk(func(rule PredicateRule) {
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

// CheckEffectiveness identifies controls that never triggered across the
// provided dataset. This is a diagnostic tool to find misconfigured or
// obsolete rules.
func CheckEffectiveness(controls []ControlDefinition, snapshots []asset.Snapshot, eval PredicateEval) []diag.Issue {
	if eval == nil {
		return nil
	}

	var issues []diag.Issue
	for _, ctl := range controls {
		if !isTriggered(ctl, snapshots, eval) {
			issues = append(issues, diag.New(diag.CodeControlNeverMatches).
				Warning().
				Action("Check predicate field paths or verify if all resources are currently safe.").
				WithMap(buildCtx(&ctl, nil)).
				Build())
		}
	}
	return issues
}

// isTriggered determines if a control matches at least one asset.
// Short-circuits on the first match.
func isTriggered(ctl ControlDefinition, snapshots []asset.Snapshot, eval PredicateEval) bool {
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
