package dto

import (
	"github.com/sufield/stave/internal/core/evaluation/coverage"
)

// CoveragePostureDTO mirrors coverage.CoverageIndex on the JSON wire.
// The outer key is the alternative tool's identifier; the inner key is
// the domain identifier (e.g., s3, iam) declared by the inventory.
type CoveragePostureDTO map[string]map[string]DomainCoverageDTO

// DomainCoverageDTO is the per-(tool, domain) entry. Total is 0 when no
// inventory file is loaded for the tool, in which case NotCoveredChecks
// is omitted as well.
type DomainCoverageDTO struct {
	Covered          int      `json:"covered"`
	Total            int      `json:"total"`
	NotCoveredChecks []string `json:"not_covered_checks"`
}

// FromCoverageIndex projects a coverage.CoverageIndex into the JSON DTO
// shape. Returns nil when the index is nil or empty so the marshaler
// can omit the field via omitempty.
func FromCoverageIndex(idx *coverage.CoverageIndex) CoveragePostureDTO {
	if idx == nil || len(idx.ByTool) == 0 {
		return nil
	}
	out := make(CoveragePostureDTO, len(idx.ByTool))
	for tool, domains := range idx.ByTool {
		domainsOut := make(map[string]DomainCoverageDTO, len(domains))
		for domain, dc := range domains {
			notCovered := dc.NotCoveredChecks
			if notCovered == nil {
				notCovered = []string{}
			}
			domainsOut[domain] = DomainCoverageDTO{
				Covered:          dc.Covered,
				Total:            dc.Total,
				NotCoveredChecks: notCovered,
			}
		}
		out[tool] = domainsOut
	}
	return out
}
