// Package deps provides static dependency extraction from Stave
// control predicates. Returns the set of property paths a predicate
// reads, without evaluating the predicate or requiring observations.
package deps

import (
	"errors"
	"slices"

	policy "github.com/sufield/stave/internal/core/controldef"
)

// ErrAliasedPredicate indicates the control uses unsafe_predicate_alias
// and its dependencies cannot be extracted statically.
var ErrAliasedPredicate = errors.New("predicate uses alias — static dependency extraction not supported")

// Extract returns the sorted, deduplicated set of property paths
// that the predicate reads. Returns ErrAliasedPredicate if the
// control uses an opaque predicate alias.
func Extract(pred *policy.UnsafePredicate) ([]string, error) {
	if pred == nil {
		return nil, nil
	}
	if len(pred.Any) == 0 && len(pred.All) == 0 {
		return nil, nil
	}

	seen := make(map[string]struct{})
	pred.Walk(func(rule policy.PredicateRule) {
		if rule.Field.IsZero() {
			return
		}
		seen[rule.Field.String()] = struct{}{}
	})

	paths := make([]string, 0, len(seen))
	for p := range seen {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	return paths, nil
}

// ExtractFromControl extracts dependencies from a control definition.
// Returns ErrAliasedPredicate if the control uses unsafe_predicate_alias.
func ExtractFromControl(ctl *policy.ControlDefinition) ([]string, error) {
	if ctl.UnsafePredicateAlias != "" {
		return nil, ErrAliasedPredicate
	}
	return Extract(&ctl.UnsafePredicate)
}
