package main

import (
	"slices"
	"strings"
)

func deduplicateGaps(results []*EngineResult) (multi, single []Gap) {
	type entry struct {
		gap     Gap
		sources []string
	}

	seen := make(map[string]*entry)
	for _, r := range results {
		for _, g := range r.GapsFound {
			key := strings.ToLower(g.Service + ":" + g.Property)
			if e, ok := seen[key]; ok {
				e.sources = append(e.sources, g.Source)
				if severityRank(g.Severity) > severityRank(e.gap.Severity) {
					e.gap.Severity = g.Severity
				}
				e.gap.Taxonomy = mergeTaxonomy(e.gap.Taxonomy, g.Taxonomy)
			} else {
				seen[key] = &entry{
					gap:     g,
					sources: []string{g.Source},
				}
			}
		}
	}

	for _, e := range seen {
		e.gap.Source = strings.Join(e.sources, " + ")
		if len(e.sources) > 1 {
			if e.gap.Confidence == "Medium" || e.gap.Confidence == "Low" {
				e.gap.Confidence = "High"
			}
			multi = append(multi, e.gap)
		} else {
			single = append(single, e.gap)
		}
	}

	sortGaps(multi)
	sortGaps(single)
	return multi, single
}

func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func mergeTaxonomy(a, b []string) []string {
	set := make(map[string]bool, len(a)+len(b))
	for _, s := range a {
		set[s] = true
	}
	for _, s := range b {
		set[s] = true
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

func sortGaps(gaps []Gap) {
	slices.SortFunc(gaps, func(a, b Gap) int {
		if d := severityRank(b.Severity) - severityRank(a.Severity); d != 0 {
			return d
		}
		if a.Service != b.Service {
			if a.Service < b.Service {
				return -1
			}
			return 1
		}
		if a.Property < b.Property {
			return -1
		}
		if a.Property > b.Property {
			return 1
		}
		return 0
	})
}

func gapKey(g Gap) string {
	return strings.ToLower(g.Service + ":" + g.Property)
}
