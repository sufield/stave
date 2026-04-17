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
	var results []SearchResult

	for i := range controls {
		ctl := &controls[i]

		if query != "" && !matchesQuery(ctl, query) {
			continue
		}
		if f.Domain != "" && !strings.Contains(strings.ToLower(string(ctl.ID)), strings.ToLower(f.Domain)) {
			continue
		}
		if f.Severity != "" && ctl.Severity.String() != strings.ToLower(f.Severity) {
			continue
		}
		if f.AttackStage != "" && ctl.AttackStage() != f.AttackStage {
			continue
		}
		if f.Profile != "" && !hasFramework(ctl, f.Profile) {
			continue
		}

		sr := SearchResult{
			ControlID:   string(ctl.ID),
			Name:        ctl.Name,
			Severity:    ctl.Severity.String(),
			Domain:      extractDomain(string(ctl.ID)),
			AttackStage: ctl.AttackStage(),
		}
		for fw := range ctl.Compliance {
			sr.Frameworks = append(sr.Frameworks, string(fw))
		}
		slices.Sort(sr.Frameworks)
		results = append(results, sr)
	}

	return results
}

func matchesQuery(ctl *policy.ControlDefinition, query string) bool {
	return strings.Contains(strings.ToLower(string(ctl.ID)), query) ||
		strings.Contains(strings.ToLower(ctl.Name), query) ||
		strings.Contains(strings.ToLower(ctl.Description), query)
}

func hasFramework(ctl *policy.ControlDefinition, profile string) bool {
	for fw := range ctl.Compliance {
		if strings.Contains(strings.ToLower(string(fw)), strings.ToLower(profile)) {
			return true
		}
	}
	return false
}

func extractDomain(controlID string) string {
	parts := strings.Split(controlID, ".")
	if len(parts) >= 2 {
		return strings.ToLower(parts[1])
	}
	return ""
}
