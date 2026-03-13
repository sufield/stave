package artifacts

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/diagnose"
	"github.com/sufield/stave/internal/adapters/input/controls/builtin"
	packs "github.com/sufield/stave/internal/builtin/pack"
	predicates "github.com/sufield/stave/internal/builtin/predicate"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/metadata"
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

func (r *ListRunner) formatOutput(cfg ListConfig, rows []ControlRow) error {
	format := strings.ToLower(strings.TrimSpace(cfg.Format))

	if format == "json" {
		return jsonutil.WriteIndented(cfg.Stdout, rows)
	}

	cols, err := parseColumns(cfg.Columns)
	if err != nil {
		return err
	}

	switch format {
	case "csv":
		return r.writeCSV(cfg.Stdout, rows, cols, !cfg.NoHeaders)
	case "text":
		return r.writeTable(cfg.Stdout, rows, cols, !cfg.NoHeaders)
	default:
		return fmt.Errorf("unsupported --format %q (use: text, json, csv)", cfg.Format)
	}
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

func (r *ListRunner) writeCSV(w io.Writer, rows []ControlRow, cols []string, header bool) error {
	cw := csv.NewWriter(w)
	if header {
		if err := cw.Write(cols); err != nil {
			return err
		}
	}
	for _, row := range rows {
		record := make([]string, len(cols))
		for i, c := range cols {
			record[i] = fieldValue(row, c)
		}
		if err := cw.Write(record); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func (r *ListRunner) writeTable(w io.Writer, rows []ControlRow, cols []string, header bool) error {
	if len(rows) == 0 {
		_, err := fmt.Fprintln(w, "No controls found.")
		return err
	}

	widths := make([]int, len(cols))
	for i, c := range cols {
		widths[i] = len(c)
	}
	for _, row := range rows {
		for i, c := range cols {
			if l := len(fieldValue(row, c)); l > widths[i] {
				widths[i] = l
			}
		}
	}

	printLine := func(vals []string) error {
		for i, v := range vals {
			if i > 0 {
				if _, err := fmt.Fprint(w, "  "); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprintf(w, "%-*s", widths[i], v); err != nil {
				return err
			}
		}
		_, err := fmt.Fprintln(w)
		return err
	}

	if header {
		if err := printLine(cols); err != nil {
			return err
		}
	}

	for _, row := range rows {
		vals := make([]string, len(cols))
		for i, c := range cols {
			vals[i] = fieldValue(row, c)
		}
		if err := printLine(vals); err != nil {
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

// --- Cobra Command Constructors ---

// NewControlsCmd constructs the controls command tree with closure-scoped flags.
func NewControlsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "controls",
		Short: "Work with control definitions",
		Long: `Controls groups commands for discovering and understanding control
definitions used by Stave.

Examples:
  stave controls list --controls ./controls
  stave controls explain CTL.S3.PUBLIC.001 --controls ./controls` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
	}

	cmd.AddCommand(newControlsListCmd())
	cmd.AddCommand(newControlsExplainCmd())
	cmd.AddCommand(newControlsAliasesCmd())
	cmd.AddCommand(newControlsAliasExplainCmd())

	return cmd
}

func newControlsListCmd() *cobra.Command {
	cfg := ListConfig{}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List control IDs and names",
		Long: `List loads controls from a directory and prints concise metadata.

Examples:
  stave controls list --controls ./controls
  stave controls list --controls ./controls --format json
  stave controls list --controls ./controls --format csv --columns id,name` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg.Stdout = cmd.OutOrStdout()
			runner := &ListRunner{Provider: compose.ActiveProvider()}
			return runner.Run(cmd.Context(), cfg)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&cfg.Dir, "controls", "i", "controls/s3", "Path to control definitions directory")
	cmd.Flags().StringVarP(&cfg.Columns, "columns", "c", "id,name,type", "Comma-separated columns: id,name,type,severity,domain")
	cmd.Flags().StringVarP(&cfg.SortBy, "sort", "s", "id", "Sort column: id,name,type,severity,domain")
	cmd.Flags().StringVarP(&cfg.Format, "format", "f", "text", "Output format: text, json, csv")
	cmd.Flags().BoolVar(&cfg.NoHeaders, "no-headers", false, "Hide headers for table/csv output")
	cmd.Flags().BoolVar(&cfg.UseBuiltIn, "built-in", false, "List built-in embedded controls instead of filesystem")
	cmd.Flags().BoolVar(&cfg.ListPacks, "packs", false, "List built-in control packs instead of controls")

	return cmd
}

func newControlsExplainCmd() *cobra.Command {
	var controlsDir string

	cmd := &cobra.Command{
		Use:   "explain <control-id>",
		Short: "Explain a specific control",
		Long: `Explain loads one control and prints matched fields, rule expectations,
and a minimal observation snippet.

Examples:
  stave controls explain CTL.S3.PUBLIC.001 --controls ./controls
  stave controls explain CTL.S3.PUBLIC.001 --controls ./controls --format json` + metadata.OfflineHelpSuffix,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			explainer := diagnose.NewExplainer(compose.ActiveProvider())
			return explainer.Run(cmd.Context(), diagnose.ExplainRequest{
				ControlID:   args[0],
				ControlsDir: controlsDir,
				Format:      ui.OutputFormatText,
				Stdout:      cmd.OutOrStdout(),
			})
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVar(&controlsDir, "controls", "controls/s3", "Path to control definitions directory")

	return cmd
}

func newControlsAliasesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "aliases",
		Short: "List built-in semantic predicate aliases",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			names := predicates.ListAliases()
			for _, name := range names {
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), name); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

func newControlsAliasExplainCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "alias-explain <alias>",
		Short: "Show expanded predicate for an alias",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			expanded, ok := predicates.Resolve(strings.TrimSpace(args[0]))
			if !ok {
				return fmt.Errorf("unknown alias %q (available: %s)", args[0], strings.Join(predicates.ListAliases(), ", "))
			}
			return jsonutil.WriteIndented(cmd.OutOrStdout(), map[string]any{
				"alias":    args[0],
				"expanded": expanded,
			})
		},
	}
}
