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
func GroupViolationsByDomain(rows []evaluation.ResourceCheck) []DomainCount {
	if len(rows) == 0 {
		return nil
	}

	counts := make(map[kernel.AssetDomain]int, len(rows)/10)
	for i := range rows {
		if !rows[i].IsViolation() {
			continue
		}

		domainStr := string(rows[i].AssetDomain)
		needsLowerTrim := false
		for j := 0; j < len(domainStr); j++ {
			c := domainStr[j]
			if (c >= 'A' && c <= 'Z') || c == ' ' || c == '\t' || c == '\n' || c == '\r' {
				needsLowerTrim = true
				break
			}
		}
		var d kernel.AssetDomain
		if needsLowerTrim {
			d = kernel.AssetDomain(strings.ToLower(strings.TrimSpace(domainStr)))
		} else {
			d = rows[i].AssetDomain
		}
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
