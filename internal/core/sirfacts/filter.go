package sirfacts

var catalogPredicates = map[string]struct{}{
	"has_severity":           {},
	"has_type":               {},
	"has_domain":             {},
	"has_intent_rationale":   {},
	"has_forbidden_state":    {},
	"has_exposure_window":    {},
	"has_vendor":             {},
	"first_seen_at":          {},
	"last_seen_at":           {},
	"contributed_by":         {},
	"has_data_event_logging": {},
}

func FilterOutCatalog(facts []Fact) []Fact {
	out := make([]Fact, 0, len(facts)/2)
	for i := range facts {
		if _, ok := catalogPredicates[facts[i].Predicate]; !ok {
			out = append(out, facts[i])
		}
	}
	return out
}
