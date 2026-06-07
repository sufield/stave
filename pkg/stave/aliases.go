package stave

import (
	predicates "github.com/sufield/stave/internal/adapters/predicate"
	domainpredicate "github.com/sufield/stave/internal/core/predicate"
)

// AliasInfo describes one semantic predicate alias — the flattened form
// [ListPredicateAliases] returns. The JSON tags match the wire shape the
// `stave inspect aliases` command emits.
type AliasInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"`
	Service     string `json:"service"`
}

// ListPredicateAliases returns metadata for every semantic predicate
// alias matching the category filter (pass "" for all). It is the
// library entry point behind `stave inspect aliases`.
func ListPredicateAliases(category string) []AliasInfo {
	infos := predicates.DefaultAliasRegistry().ListAliasInfo(category)
	out := make([]AliasInfo, len(infos))
	for i, info := range infos {
		out[i] = AliasInfo{
			Name:        info.Name,
			Description: info.Description,
			Category:    info.Category,
			Service:     info.Service,
		}
	}
	return out
}

// SupportedOperators returns the predicate operators Stave supports, as
// strings.
func SupportedOperators() []string {
	ops := domainpredicate.ListSupported()
	out := make([]string, len(ops))
	for i, op := range ops {
		out[i] = string(op)
	}
	return out
}
