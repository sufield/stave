package main

import (
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/adapters/compliance"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

type matcher struct {
	catalog  *policy.Catalog
	byService map[string][]controlEntry
}

type controlEntry struct {
	id          string
	name        string
	description string
	tags        []kernel.ScopeTag
}

func newMatcher(catalog *policy.Catalog) *matcher {
	m := &matcher{
		catalog:   catalog,
		byService: make(map[string][]controlEntry),
	}
	for _, ctl := range catalog.List() {
		entry := controlEntry{
			id:          string(ctl.ID),
			name:        ctl.Name,
			description: ctl.Description,
			tags:        ctl.ScopeTags,
		}
		for _, tag := range ctl.ScopeTags {
			svc := strings.ReplaceAll(strings.ToLower(string(tag)), "-", "")
			m.byService[svc] = append(m.byService[svc], entry)
		}
	}
	return m
}

func (m *matcher) diff(fw *compliance.Framework) DiffReport {
	report := DiffReport{
		Framework: fw.DisplayName(),
		Version:   fw.Version,
		Source:     fw.Source,
	}

	for _, check := range fw.Checks {
		result := m.match(check)
		report.Results = append(report.Results, result)
	}

	report.computeSummary()
	return report
}

func (m *matcher) match(check compliance.Check) MatchResult {
	if !check.IsInScope() {
		return MatchResult{
			Check:  check,
			Status: "out_of_scope",
			Notes:  "requirement is " + check.Scope + ", not configuration",
		}
	}

	svc := check.NormalizedService()
	controls := m.byService[svc]
	if alias, ok := serviceAliases[svc]; ok {
		controls = append(controls, m.byService[alias]...)
	}

	exact := m.searchExact(controls, check)
	if len(exact) > 0 {
		return MatchResult{
			Check:      check,
			Status:     "covered",
			ControlIDs: exact,
			Confidence: "exact",
		}
	}

	keyword := m.searchKeyword(controls, check)
	if len(keyword) > 0 {
		return MatchResult{
			Check:      check,
			Status:     "partial",
			ControlIDs: keyword,
			Confidence: "keyword",
			Notes:      "related controls found, exact property match uncertain",
		}
	}

	if len(controls) == 0 {
		return MatchResult{
			Check:  check,
			Status: "gap",
			Notes:  "zero controls for service " + check.Service,
		}
	}

	return MatchResult{
		Check:  check,
		Status: "gap",
		Notes:  formatGapNote(check.Service, len(controls)),
	}
}

func (m *matcher) searchExact(controls []controlEntry, check compliance.Check) []string {
	desc := strings.ToLower(check.Description)
	prop := strings.ToLower(check.Property)

	var ids []string
	for _, ctl := range controls {
		ctlName := strings.ToLower(ctl.name)
		ctlDesc := strings.ToLower(ctl.description)

		if prop != "" && (strings.Contains(ctlName, prop) || strings.Contains(ctlDesc, prop)) {
			ids = append(ids, ctl.id)
			continue
		}

		keywords := extractKeywords(desc)
		matched := 0
		for _, kw := range keywords {
			if strings.Contains(ctlName, kw) || strings.Contains(ctlDesc, kw) {
				matched++
			}
		}
		if len(keywords) >= 3 && matched >= len(keywords)*3/4 {
			ids = append(ids, ctl.id)
		}
	}
	return ids
}

func (m *matcher) searchKeyword(controls []controlEntry, check compliance.Check) []string {
	desc := strings.ToLower(check.Description)
	keywords := extractKeywords(desc)
	if len(keywords) == 0 {
		return nil
	}

	var ids []string
	for _, ctl := range controls {
		ctlText := strings.ToLower(ctl.name + " " + ctl.description)
		matched := 0
		for _, kw := range keywords {
			if strings.Contains(ctlText, kw) {
				matched++
			}
		}
		if matched >= 2 {
			ids = append(ids, ctl.id)
		}
	}
	return ids
}

var stopWords = map[string]bool{
	"is": true, "the": true, "a": true, "an": true, "for": true,
	"in": true, "of": true, "to": true, "or": true, "and": true,
	"has": true, "are": true, "no": true, "not": true, "all": true,
	"that": true, "have": true, "with": true, "be": true, "at": true,
	"ensure": true, "enabled": true, "exists": true, "configured": true,
}

func extractKeywords(text string) []string {
	words := strings.Fields(text)
	var keywords []string
	for _, w := range words {
		w = strings.Trim(strings.ToLower(w), ".,;:\"'()[]{}!?")
		if len(w) < 3 || stopWords[w] {
			continue
		}
		keywords = append(keywords, w)
		if syns, ok := synonyms[w]; ok {
			keywords = append(keywords, syns...)
		}
	}
	return keywords
}

// synonyms maps compliance framework vocabulary to control catalog
// vocabulary. Bridges the naming gap between frameworks (which use
// abstract governance terms) and controls (which use concrete AWS
// property names). Each entry improves matching for ALL frameworks.
var synonyms = map[string][]string{
	"segmentation":  {"subnet", "security group", "nacl"},
	"segregation":   {"subnet", "security group", "nacl", "isolation"},
	"segment":       {"subnet", "security group"},
	"segregat":      {"subnet", "isolation"},
	"tenant":        {"isolation", "vpc"},
	"failure":       {"alarm", "alert"},
	"anomal":        {"alarm", "alert", "detection"},
	"anomalies":     {"alarm", "alert", "detection"},
	"notification":  {"alarm", "alert", "sns"},
	"alerting":      {"alarm", "cloudwatch"},
	"disposal":      {"lifecycle", "deletion", "wipe"},
	"inventory":     {"discovery", "catalog", "list"},
	"hardening":     {"imdsv2", "ssm", "patching"},
	"harden":        {"imdsv2", "ssm", "patching"},
	"compatibility": {"version", "upgrade", "patching"},
	"capacity":      {"autoscaling", "scaling", "alarm"},
	"scaling":       {"autoscaling", "auto-scaling"},
	"exhaustion":    {"alarm", "autoscaling", "scaling"},
	"resilience":    {"backup", "multi-az", "failover", "autoscaling"},
	"deputy":        {"assumerole", "sourceaccount", "condition"},
	"perimeter":     {"principalorgid", "condition", "scp"},
	"confused":      {"assumerole", "sourceaccount"},
}

var serviceAliases = map[string]string{
	"inspector":   "inspector2",
	"netfirewall": "networkfirewall",
}

func formatGapNote(service string, count int) string {
	return fmt.Sprintf("service has %d controls but none match this property", count)
}
