package sirfacts

var catalogPredicates = map[string]bool{
	"has_severity":           true,
	"has_type":               true,
	"has_domain":             true,
	"has_intent_rationale":   true,
	"has_forbidden_state":    true,
	"has_exposure_window":    true,
	"has_vendor":             true,
	"first_seen_at":          true,
	"last_seen_at":           true,
	"contributed_by":         true,
	"has_data_event_logging": true,
}

func FilterOutCatalog(facts []Fact) []Fact {
	out := make([]Fact, 0, len(facts)/2)
	for i := range facts {
		if !catalogPredicates[facts[i].Predicate] {
			out = append(out, facts[i])
		}
	}
	return out
}
