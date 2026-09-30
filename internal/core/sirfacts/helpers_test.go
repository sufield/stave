package sirfacts

import "slices"

func uniquePredicates(facts []Fact) []string {
	seen := make(map[string]struct{}, len(facts))
	for _, f := range facts {
		seen[f.Predicate] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}
