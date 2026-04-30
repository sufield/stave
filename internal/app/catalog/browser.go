package catalog

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	policy "github.com/sufield/stave/internal/core/controldef"
)

// DiscoveryRequest defines the parameters for searching the policy catalog.
type DiscoveryRequest struct {
	PolicySource   string
	Fields         string
	OrderBy        string
	OutputFormat   string
	HideHeaders    bool
	IncludeBuiltIn bool
	IncludePacks   bool
}

// PolicyEntry represents a high-level summary of a security control for catalog display.
type PolicyEntry struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Risk   string `json:"risk,omitempty"`
	Domain string `json:"domain,omitempty"`
}

// CatalogBrowser orchestrates the discovery and presentation of security controls.
type CatalogBrowser struct {
	Provider PolicySource
}

// Browse retrieves security policies from the provider, summarizes them, and applies ordering.
func (b *CatalogBrowser) Browse(ctx context.Context, req DiscoveryRequest) ([]PolicyEntry, error) {
	controls, err := b.Provider.Fetch(ctx)
	if err != nil {
		return nil, fmt.Errorf("policy discovery failed: %w", err)
	}
	entries := SummarizePolicies(controls)
	if err := OrderEntries(entries, req.OrderBy); err != nil {
		return nil, err
	}
	return entries, nil
}

// SummarizePolicies transforms control definitions into display-friendly entries.
func SummarizePolicies(controls []policy.ControlDefinition) []PolicyEntry {
	entries := make([]PolicyEntry, 0, len(controls))
	for i := range controls {
		c := &controls[i]
		entries = append(entries, PolicyEntry{
			ID:     c.ID.String(),
			Name:   c.Name,
			Type:   c.Type.String(),
			Risk:   c.Severity.String(),
			Domain: string(c.Domain),
		})
	}
	return entries
}

// OrderEntries sorts policy entries by the requested attribute.
func OrderEntries(entries []PolicyEntry, orderBy string) error {
	key := strings.ToLower(strings.TrimSpace(orderBy))
	var less func(i, j int) bool

	switch key {
	case "id":
		less = func(i, j int) bool { return entries[i].ID < entries[j].ID }
	case "name":
		less = func(i, j int) bool { return entries[i].Name < entries[j].Name }
	case "type":
		less = func(i, j int) bool { return entries[i].Type < entries[j].Type }
	case "risk":
		less = func(i, j int) bool { return entries[i].Risk < entries[j].Risk }
	case "domain":
		less = func(i, j int) bool { return entries[i].Domain < entries[j].Domain }
	default:
		return fmt.Errorf("invalid order attribute %q (available: id, name, type, risk, domain)", orderBy)
	}

	sort.Slice(entries, less)
	return nil
}

// SelectFields validates and returns the requested field names for display.
func SelectFields(raw string) ([]string, error) {
	valid := map[string]bool{"id": true, "name": true, "type": true, "risk": true, "domain": true}
	var selected []string
	seen := make(map[string]bool)

	for _, p := range strings.Split(raw, ",") {
		f := strings.ToLower(strings.TrimSpace(p))
		if f == "" {
			continue
		}
		if !valid[f] {
			return nil, fmt.Errorf("invalid field selection %q (allowed: id, name, type, risk, domain)", f)
		}
		if !seen[f] {
			selected = append(selected, f)
			seen[f] = true
		}
	}
	if len(selected) == 0 {
		return nil, errors.New("at least one field must be selected (id, name, type, risk, domain)")
	}
	return selected, nil
}

// GetAttribute extracts a named attribute from a PolicyEntry.
func GetAttribute(entry PolicyEntry, field string) string {
	switch field {
	case "id":
		return entry.ID
	case "name":
		return entry.Name
	case "type":
		return entry.Type
	case "risk":
		return entry.Risk
	case "domain":
		return entry.Domain
	default:
		return ""
	}
}
