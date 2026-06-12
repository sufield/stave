// Package catalogsearch provides keyword search and filtering over
// the control catalog for discovery and deduplication.
package catalogsearch

import (
	"slices"
	"strings"

	policy "github.com/sufield/stave/internal/core/controldef"
)

// SearchResult holds one matching control.
type SearchResult struct {
	ControlID   string   `json:"control_id"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Domain      string   `json:"domain"`
	Frameworks  []string `json:"frameworks,omitempty"`
	AttackStage string   `json:"attack_stage,omitempty"`
}

// Filter constrains the search.
type Filter struct {
	Query       string
	Domain      string
	Severity    string
	AttackStage string
	Profile     string
}

// Search finds controls matching the filter criteria.
func Search(controls []policy.ControlDefinition, f Filter) []SearchResult {
	query := strings.ToLower(f.Query)
	domainFilter := strings.ToLower(f.Domain)
	profileFilter := strings.ToLower(f.Profile)
	var results []SearchResult

	for i := range controls {
		ctl := &controls[i]

		if query != "" && !matchesQuery(ctl, query) {
			continue
		}
		if domainFilter != "" && !strings.Contains(strings.ToLower(string(ctl.ID)), domainFilter) {
			continue
		}
		if f.Severity != "" && !ctl.Severity.Matches(f.Severity) {
			continue
		}
		if f.AttackStage != "" && string(ctl.AttackStage()) != f.AttackStage {
			continue
		}
		if profileFilter != "" && !hasFramework(ctl, profileFilter) {
			continue
		}

		sr := SearchResult{
			ControlID:   string(ctl.ID),
			Name:        ctl.Name,
			Severity:    ctl.Severity.String(),
			Domain:      extractDomain(string(ctl.ID)),
			AttackStage: string(ctl.AttackStage()),
		}
		for fw := range ctl.Compliance {
			sr.Frameworks = append(sr.Frameworks, string(fw))
		}
		slices.Sort(sr.Frameworks)
		results = append(results, sr)
	}

	return results
}

func matchesQuery(ctl *policy.ControlDefinition, queryLower string) bool {
	return strings.Contains(strings.ToLower(string(ctl.ID)), queryLower) ||
		strings.Contains(strings.ToLower(ctl.Name), queryLower) ||
		strings.Contains(strings.ToLower(ctl.Description), queryLower)
}

func hasFramework(ctl *policy.ControlDefinition, profileLower string) bool {
	for fw := range ctl.Compliance {
		if strings.Contains(strings.ToLower(string(fw)), profileLower) {
			return true
		}
	}
	return false
}

func extractDomain(controlID string) string {
	_, rest, ok := strings.Cut(controlID, ".")
	if !ok {
		return ""
	}
	prov, _, _ := strings.Cut(rest, ".")
	return strings.ToLower(prov)
}
