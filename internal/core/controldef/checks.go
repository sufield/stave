package controldef

import (
	"maps"
	"slices"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/diag"
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

	return slices.Sorted(maps.Keys(missingSet))
}

// CheckEffectiveness identifies controls that never triggered across the
// provided dataset. This is a diagnostic tool to find misconfigured or
// obsolete rules.
func CheckEffectiveness(controls []ControlDefinition, snapshots []asset.Snapshot, eval PredicateEval) []diag.Finding {
	if eval == nil {
		return nil
	}

	var issues []diag.Finding
	for i := range controls {
		ctl := &controls[i]
		if !isTriggered(ctl, snapshots, eval) {
			issues = append(issues, diag.NewFinding(diag.RuleControlNeverMatches).
				Warning().
				Remediation("Check predicate field paths or verify if all resources are currently safe.").
				Attributes(ctl.issueContext(nil)).
				Build())
		}
	}
	return issues
}

// isTriggered determines if a control matches at least one asset.
// Short-circuits on the first match. Pointer receiver so the
// 584-byte ControlDefinition isn't copied per call (gocritic
// hugeParam threshold) — the eval boundary still takes the
// struct by value because the PredicateEval signature is locked
// by every callsite in the engine.
func isTriggered(ctl *ControlDefinition, snapshots []asset.Snapshot, eval PredicateEval) bool {
	for _, snap := range snapshots {
		for _, a := range snap.Assets {
			if !ctl.AppliesToAssetType(a.Type) {
				continue
			}
			unsafe, err := eval(*ctl, a, snap.Identities)
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
	for i := range p.Any {
		r := &p.Any[i]
		r.Walk(visit)
	}
	for i := range p.All {
		r := &p.All[i]
		r.Walk(visit)
	}
}

// Walk visits the current rule and recursively visits all child rules.
func (r PredicateRule) Walk(visit func(PredicateRule)) {
	visit(r)
	for i := range r.Any {
		child := &r.Any[i]
		child.Walk(visit)
	}
	for i := range r.All {
		child := &r.All[i]
		child.Walk(visit)
	}
}
