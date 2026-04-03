package text

import (
	"cmp"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

// DomainCount represents the number of violations in a specific business domain.
type DomainCount struct {
	Domain kernel.AssetDomain
	Count  int
}

// GroupViolationsByDomain aggregates violation rows into sorted counts by asset domain.
func GroupViolationsByDomain(rows []evaluation.Row) []DomainCount {
	if len(rows) == 0 {
		return nil
	}

	counts := make(map[kernel.AssetDomain]int, len(rows)/10)
	for i := range rows {
		if rows[i].Decision != evaluation.DecisionViolation {
			continue
		}

		d := kernel.AssetDomain(strings.ToLower(strings.TrimSpace(string(rows[i].AssetDomain))))
		if d == "" {
			d = "unknown"
		}
		counts[d]++
	}

	res := make([]DomainCount, 0, len(counts))
	for d, c := range counts {
		res = append(res, DomainCount{Domain: d, Count: c})
	}

	slices.SortFunc(res, func(a, b DomainCount) int {
		return cmp.Compare(a.Domain, b.Domain)
	})

	return res
}
