package artifacts

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/adapters/input/controls/builtin"
	packs "github.com/sufield/stave/internal/builtin/pack"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/pkg/jsonutil"
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
	Stdout     io.Writer
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
	Provider *compose.Provider
}

// Run executes the list operation.
func (r *ListRunner) Run(ctx context.Context, cfg ListConfig) error {
	if cfg.ListPacks {
		return r.listPacks(cfg)
	}

	controls, err := r.loadData(ctx, cfg)
	if err != nil {
		return err
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

	if err := r.sortRows(rows, cfg.SortBy); err != nil {
		return err
	}

	return r.formatOutput(cfg, rows)
}

func (r *ListRunner) loadData(ctx context.Context, cfg ListConfig) ([]policy.ControlDefinition, error) {
	if cfg.UseBuiltIn {
		controls, err := builtin.LoadAll(ctx)
		if err != nil {
			return nil, fmt.Errorf("load built-in controls: %w", err)
		}
		return controls, nil
	}

	repo, err := r.Provider.NewControlRepo()
	if err != nil {
		return nil, fmt.Errorf("create control loader: %w", err)
	}
	controls, err := repo.LoadControls(ctx, strings.TrimSpace(cfg.Dir))
	if err != nil {
		return nil, fmt.Errorf("load controls: %w", err)
	}
	return controls, nil
}

func (r *ListRunner) sortRows(rows []ControlRow, sortBy string) error {
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

func (r *ListRunner) listPacks(cfg ListConfig) error {
	items, err := packs.ListPacks()
	if err != nil {
		return err
	}

	if strings.ToLower(strings.TrimSpace(cfg.Format)) == "json" {
		return jsonutil.WriteIndented(cfg.Stdout, items)
	}

	if len(items) == 0 {
		_, err := fmt.Fprintln(cfg.Stdout, "No packs found.")
		return err
	}

	for _, p := range items {
		if _, err := fmt.Fprintf(cfg.Stdout, "%s\t%s\n", p.Name, p.Description); err != nil {
			return err
		}
	}
	return nil
}

// --- Internal Helpers ---

func parseColumns(raw string) ([]string, error) {
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

func fieldValue(row ControlRow, col string) string {
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
