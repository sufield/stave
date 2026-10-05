// Package catalogsearch provides keyword search and filtering over
// the control catalog for discovery and deduplication.
package catalogsearch

import (
	"slices"
	"strings"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/util/strutil"
)

// ComplianceFrameworks is a domain collection of policy.ComplianceFramework items with query methods.
type ComplianceFrameworks []policy.ComplianceFramework

// Len returns the number of compliance frameworks in the collection.
func (cf ComplianceFrameworks) Len() int {
	return len(cf)
}

// Contains reports whether the target framework is present in the collection.
func (cf ComplianceFrameworks) Contains(target policy.ComplianceFramework) bool {
	return slices.Contains(cf, target)
}

// SearchResult holds one matching control.
type SearchResult struct {
	ControlID   kernel.ControlID     `json:"control_id"`
	Name        string               `json:"name"`
	Severity    policy.Severity      `json:"severity"`
	Domain      kernel.AssetType     `json:"domain"`
	Frameworks  ComplianceFrameworks `json:"frameworks,omitempty"`
	AttackStage kernel.AttackStage   `json:"attack_stage,omitempty"`
}

// SearchResults represents a collection of SearchResult items with query methods.
type SearchResults []SearchResult

// Len returns the count of search results.
func (sr SearchResults) Len() int {
	return len(sr)
}

// BySeverity returns a filtered slice of SearchResult items matching the given severity.
func (sr SearchResults) BySeverity(sev policy.Severity) SearchResults {
	var filtered SearchResults
	for _, r := range sr {
		if r.Severity == sev {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

// ByDomain returns a filtered slice of SearchResult items matching the given domain asset type.
func (sr SearchResults) ByDomain(domain kernel.AssetType) SearchResults {
	var filtered SearchResults
	for _, r := range sr {
		if r.Domain == domain {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

// SearchQuery represents a catalog search keyword query.
type SearchQuery string

// String returns the raw string value of the search query.
func (q SearchQuery) String() string {
	return string(q)
}

// IsEmpty reports whether the search query is blank or empty.
func (q SearchQuery) IsEmpty() bool {
	return strings.TrimSpace(string(q)) == ""
}

// Lower returns the search query converted to lower case.
func (q SearchQuery) Lower() string {
	return toLower(string(q))
}

// Normalized returns the search query trimmed of whitespace and converted to lower case.
func (q SearchQuery) Normalized() string {
	return toLower(strings.TrimSpace(string(q)))
}

// Matches reports whether the query matches target text using case-insensitive substring search.
func (q SearchQuery) Matches(target string) bool {
	if q.IsEmpty() {
		return true
	}
	return strutil.ContainsFold(target, q.Normalized())
}

// Filter constrains the search.
type Filter struct {
	Query       SearchQuery
	Domain      kernel.AssetType
	Severity    policy.Severity
	AttackStage kernel.AttackStage
	Profile     string
}

// Search finds controls matching the filter criteria.
func Search(controls []policy.ControlDefinition, f Filter) SearchResults {
	query := f.Query.Normalized()
	domainFilter := toLower(string(f.Domain))
	profileFilter := toLower(f.Profile)
	var results SearchResults

	for i := range controls {
		ctl := &controls[i]

		if !f.Query.IsEmpty() && !matchesQuery(ctl, query) {
			continue
		}
		if domainFilter != "" && getDomain(ctl) != domainFilter {
			continue
		}
		if f.Severity != 0 && !ctl.Severity.Matches(f.Severity.String()) {
			continue
		}
		if f.AttackStage != "" && !strings.EqualFold(string(ctl.AttackStage()), string(f.AttackStage)) {
			continue
		}
		if profileFilter != "" && !hasFramework(ctl, profileFilter) {
			continue
		}

		sr := SearchResult{
			ControlID:   ctl.ID,
			Name:        ctl.Name,
			Severity:    ctl.Severity,
			Domain:      kernel.AssetType(getDomain(ctl)),
			AttackStage: ctl.AttackStage(),
			Frameworks:  make([]policy.ComplianceFramework, 0, len(ctl.Compliance)),
		}
		for fw := range ctl.Compliance {
			sr.Frameworks = append(sr.Frameworks, fw)
		}
		slices.SortFunc(sr.Frameworks, func(a, b policy.ComplianceFramework) int {
			return strings.Compare(string(a), string(b))
		})
		results = append(results, sr)
	}

	return results
}

func matchesQuery(ctl *policy.ControlDefinition, queryLower string) bool {
	return strutil.ContainsFold(string(ctl.ID), queryLower) ||
		strutil.ContainsFold(ctl.Name, queryLower) ||
		strutil.ContainsFold(ctl.Description, queryLower)
}

func hasFramework(ctl *policy.ControlDefinition, profileLower string) bool {
	for fw := range ctl.Compliance {
		if strutil.ContainsFold(string(fw), profileLower) {
			return true
		}
	}
	return false
}

func getDomain(ctl *policy.ControlDefinition) string {
	if ctl.Domain != "" {
		return toLower(string(ctl.Domain))
	}
	return extractDomain(string(ctl.ID))
}

func extractDomain(controlID string) string {
	cleanID := controlID
	if len(controlID) > 4 && strings.EqualFold(controlID[:4], "CTL.") {
		cleanID = controlID[4:]
	}
	prov, _, _ := strings.Cut(cleanID, ".")
	return toLower(prov)
}

func toLower(s string) string {
	needsLower := false
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			needsLower = true
			break
		}
	}
	if needsLower {
		return strings.ToLower(s)
	}
	return s
}
