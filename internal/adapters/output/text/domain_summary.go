package text

import (
	"cmp"
	"slices"

	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/util/strutil"
)

// DomainCount represents the number of violations in a specific business domain.
type DomainCount struct {
	Domain kernel.AssetDomain
	Count  int
}

// GroupViolationsByDomain aggregates violation rows into sorted counts by asset domain.
func GroupViolationsByDomain(rows []evaluation.ResourceCheck) []DomainCount {
	if len(rows) == 0 {
		return nil
	}

	counts := make(map[kernel.AssetDomain]int, len(rows)/10)
	for i := range rows {
		if !rows[i].IsViolation() {
			continue
		}

		d := kernel.AssetDomain(strutil.ToLowerTrim(string(rows[i].AssetDomain)))
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
