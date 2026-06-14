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
	query := toLower(f.Query)
	domainFilter := toLower(f.Domain)
	profileFilter := toLower(f.Profile)
	var results []SearchResult

	for i := range controls {
		ctl := &controls[i]

		if query != "" && !matchesQuery(ctl, query) {
			continue
		}
		if domainFilter != "" && !containsFold(string(ctl.ID), domainFilter) {
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
			Frameworks:  make([]string, 0, len(ctl.Compliance)),
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
	return containsFold(string(ctl.ID), queryLower) ||
		containsFold(ctl.Name, queryLower) ||
		containsFold(ctl.Description, queryLower)
}

func hasFramework(ctl *policy.ControlDefinition, profileLower string) bool {
	for fw := range ctl.Compliance {
		if containsFold(string(fw), profileLower) {
			return true
		}
	}
	return false
}

func containsFold(s, substr string) bool {
	if substr == "" {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	isASCII := true
	for i := 0; i < len(s); i++ {
		if s[i] >= 128 {
			isASCII = false
			break
		}
	}
	if isASCII {
		for i := 0; i < len(substr); i++ {
			if substr[i] >= 128 {
				isASCII = false
				break
			}
		}
	}
	if isASCII {
		for i := 0; i <= len(s)-len(substr); i++ {
			match := true
			for j := 0; j < len(substr); j++ {
				c1 := s[i+j]
				c2 := substr[j]
				if c1 != c2 {
					if c1 >= 'A' && c1 <= 'Z' {
						c1 += 'a' - 'A'
					}
					if c2 >= 'A' && c2 <= 'Z' {
						c2 += 'a' - 'A'
					}
					if c1 != c2 {
						match = false
						break
					}
				}
			}
			if match {
				return true
			}
		}
		return false
	}
	return strings.Contains(toLower(s), toLower(substr))
}

func extractDomain(controlID string) string {
	_, rest, ok := strings.Cut(controlID, ".")
	if !ok {
		return ""
	}
	prov, _, _ := strings.Cut(rest, ".")
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
