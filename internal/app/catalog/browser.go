package catalog

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
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
	trimmed := strings.TrimSpace(orderBy)
	if strings.EqualFold(trimmed, "id") {
		slices.SortFunc(entries, func(a, b PolicyEntry) int { return cmp.Compare(a.ID, b.ID) })
	} else if strings.EqualFold(trimmed, "name") {
		slices.SortFunc(entries, func(a, b PolicyEntry) int { return cmp.Compare(a.Name, b.Name) })
	} else if strings.EqualFold(trimmed, "type") {
		slices.SortFunc(entries, func(a, b PolicyEntry) int { return cmp.Compare(a.Type, b.Type) })
	} else if strings.EqualFold(trimmed, "risk") {
		slices.SortFunc(entries, func(a, b PolicyEntry) int { return cmp.Compare(a.Risk, b.Risk) })
	} else if strings.EqualFold(trimmed, "domain") {
		slices.SortFunc(entries, func(a, b PolicyEntry) int { return cmp.Compare(a.Domain, b.Domain) })
	} else {
		return fmt.Errorf("invalid order attribute %q (available: id, name, type, risk, domain)", orderBy)
	}

	return nil
}

// SelectFields validates and returns the requested field names for display.
func SelectFields(raw string) ([]string, error) {
	var selected []string
	seen := make(map[string]struct{}, 5)

	for p := range strings.SplitSeq(raw, ",") {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			continue
		}
		var f string
		if strings.EqualFold(trimmed, "id") {
			f = "id"
		} else if strings.EqualFold(trimmed, "name") {
			f = "name"
		} else if strings.EqualFold(trimmed, "type") {
			f = "type"
		} else if strings.EqualFold(trimmed, "risk") {
			f = "risk"
		} else if strings.EqualFold(trimmed, "domain") {
			f = "domain"
		} else {
			return nil, fmt.Errorf("invalid field selection %q (allowed: id, name, type, risk, domain)", trimmed)
		}
		if _, isSeen := seen[f]; !isSeen {
			selected = append(selected, f)
			seen[f] = struct{}{}
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
