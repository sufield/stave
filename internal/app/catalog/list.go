package catalog

import (
	"context"
	"fmt"
	"sort"
	"strings"

	policy "github.com/sufield/stave/internal/core/controldef"
)

// ListConfig defines the parameters for listing controls.
type ListConfig struct {
	Dir        string
	Columns    string
	SortBy     string
	Format     string
	NoHeaders  bool
	UseBuiltIn bool
	ListPacks  bool
}

// ControlRow represents a flattened view of a control for display.
type ControlRow struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Severity string `json:"severity,omitempty"`
	Domain   string `json:"domain,omitempty"`
}

// ListRunner orchestrates the "stave controls list" logic.
type ListRunner struct {
	Provider ControlProvider
}

// Run executes the list operation, returning rows for the cmd layer to format.
func (r *ListRunner) Run(ctx context.Context, cfg ListConfig) ([]ControlRow, error) {
	controls, err := r.Provider.Load(ctx)
	if err != nil {
		return nil, fmt.Errorf("load controls: %w", err)
	}

	rows := make([]ControlRow, 0, len(controls))
	for _, c := range controls {
		rows = append(rows, ControlRow{
			ID:       c.ID.String(),
			Name:     c.Name,
			Type:     c.Type.String(),
			Severity: c.Severity.String(),
			Domain:   c.Domain,
		})
	}

	if err := SortRows(rows, cfg.SortBy); err != nil {
		return nil, err
	}

	return rows, nil
}

// ToRows converts control definitions to display rows.
func ToRows(controls []policy.ControlDefinition) []ControlRow {
	rows := make([]ControlRow, 0, len(controls))
	for _, c := range controls {
		rows = append(rows, ControlRow{
			ID:       c.ID.String(),
			Name:     c.Name,
			Type:     c.Type.String(),
			Severity: c.Severity.String(),
			Domain:   c.Domain,
		})
	}
	return rows
}

// SortRows sorts control rows by the given column name.
func SortRows(rows []ControlRow, sortBy string) error {
	sortKey := strings.ToLower(strings.TrimSpace(sortBy))
	var less func(i, j int) bool

	switch sortKey {
	case "id":
		less = func(i, j int) bool { return rows[i].ID < rows[j].ID }
	case "name":
		less = func(i, j int) bool { return rows[i].Name < rows[j].Name }
	case "type":
		less = func(i, j int) bool { return rows[i].Type < rows[j].Type }
	case "severity":
		less = func(i, j int) bool { return rows[i].Severity < rows[j].Severity }
	case "domain":
		less = func(i, j int) bool { return rows[i].Domain < rows[j].Domain }
	default:
		return fmt.Errorf("invalid --sort %q (use: id, name, type, severity, domain)", sortBy)
	}

	sort.Slice(rows, less)
	return nil
}

// ParseColumns validates and returns the requested column names.
func ParseColumns(raw string) ([]string, error) {
	allowed := map[string]bool{"id": true, "name": true, "type": true, "severity": true, "domain": true}
	var cols []string
	seen := make(map[string]bool)

	for p := range strings.SplitSeq(raw, ",") {
		c := strings.ToLower(strings.TrimSpace(p))
		if c == "" {
			continue
		}
		if !allowed[c] {
			return nil, fmt.Errorf("invalid --columns value %q (allowed: id,name,type,severity,domain)", c)
		}
		if !seen[c] {
			cols = append(cols, c)
			seen[c] = true
		}
	}
	if len(cols) == 0 {
		return nil, fmt.Errorf("--columns must include at least one of: id,name,type,severity,domain")
	}
	return cols, nil
}

// FieldValue extracts the value for a named column from a ControlRow.
func FieldValue(row ControlRow, col string) string {
	switch col {
	case "id":
		return row.ID
	case "name":
		return row.Name
	case "type":
		return row.Type
	case "severity":
		return row.Severity
	case "domain":
		return row.Domain
	default:
		return ""
	}
}
