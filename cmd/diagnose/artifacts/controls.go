package artifacts

import (
	"context"
	"encoding/csv"
	"errors"
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
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/pkg/jsonutil"
)

type controlsListFlagsType struct {
	listDir, listCols, listSort, listFormat string
	listNoHdr, listBuiltIn, listPacks       bool
}

type controlListRow struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Severity string `json:"severity,omitempty"`
	Domain   string `json:"domain,omitempty"`
}

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
	var flags controlsListFlagsType

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
			return runControlsList(cmd, &flags)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&flags.listDir, "controls", "i", "controls/s3", "Path to control definitions directory")
	cmd.Flags().StringVarP(&flags.listCols, "columns", "c", "id,name,type", "Comma-separated columns: id,name,type,severity,domain")
	cmd.Flags().StringVarP(&flags.listSort, "sort", "s", "id", "Sort column: id,name,type,severity,domain")
	cmd.Flags().StringVarP(&flags.listFormat, "format", "f", "text", "Output format: text, json, csv")
	cmd.Flags().BoolVar(&flags.listNoHdr, "no-headers", false, "Hide headers for table/csv output")
	cmd.Flags().BoolVar(&flags.listBuiltIn, "built-in", false, "List built-in embedded controls instead of filesystem")
	cmd.Flags().BoolVar(&flags.listPacks, "packs", false, "List built-in control packs instead of controls")

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
			return runControlsExplain(cmd, args, controlsDir)
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
		RunE: func(cmd *cobra.Command, args []string) error {
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
			out := map[string]any{"alias": args[0], "expanded": expanded}
			return jsonutil.WriteIndented(cmd.OutOrStdout(), out)
		},
	}
}

func runControlsList(cmd *cobra.Command, flags *controlsListFlagsType) error {
	if flags.listPacks {
		return runControlsListPacks(cmd, flags.listFormat)
	}
	controls, err := loadControlsForList(compose.CommandContext(cmd), flags)
	if err != nil {
		return err
	}
	rows := buildControlListRows(controls)
	if err := sortControlRows(rows, flags.listSort); err != nil {
		return err
	}
	return writeControlRows(cmd.OutOrStdout(), rows, flags.listFormat, flags.listCols, !flags.listNoHdr)
}

func loadControlsForList(ctx context.Context, flags *controlsListFlagsType) ([]policy.ControlDefinition, error) {
	if flags.listBuiltIn {
		controls, err := builtin.LoadAll(ctx)
		if err != nil {
			return nil, fmt.Errorf("load built-in controls: %w", err)
		}
		return controls, nil
	}

	loader, err := compose.ActiveProvider().NewControlRepo()
	if err != nil {
		return nil, fmt.Errorf("create control loader: %w", err)
	}
	controls, err := loader.LoadControls(ctx, strings.TrimSpace(flags.listDir))
	if err != nil {
		return nil, fmt.Errorf("load controls: %w", err)
	}
	return controls, nil
}

func buildControlListRows(controls []policy.ControlDefinition) []controlListRow {
	rows := make([]controlListRow, 0, len(controls))
	for i := range controls {
		rows = append(rows, controlListRow{
			ID:       controls[i].ID.String(),
			Name:     controls[i].Name,
			Type:     controls[i].Type.String(),
			Severity: controls[i].Severity.String(),
			Domain:   controls[i].Domain,
		})
	}
	return rows
}

func sortControlRows(rows []controlListRow, sortValue string) error {
	less, err := controlSortLess(sortValue)
	if err != nil {
		return err
	}
	sort.Slice(rows, func(i, j int) bool { return less(rows[i], rows[j]) })
	return nil
}

func controlSortLess(sortValue string) (func(controlListRow, controlListRow) bool, error) {
	switch strings.ToLower(strings.TrimSpace(sortValue)) {
	case "id":
		return func(left, right controlListRow) bool { return left.ID < right.ID }, nil
	case "name":
		return func(left, right controlListRow) bool { return left.Name < right.Name }, nil
	case "type":
		return func(left, right controlListRow) bool { return left.Type < right.Type }, nil
	case "severity":
		return func(left, right controlListRow) bool { return left.Severity < right.Severity }, nil
	case "domain":
		return func(left, right controlListRow) bool { return left.Domain < right.Domain }, nil
	default:
		return nil, fmt.Errorf("invalid --sort %q (use: id, name, type, severity, domain)", sortValue)
	}
}

func writeControlRows(w io.Writer, rows []controlListRow, formatValue, columnsValue string, showHeaders bool) error {
	format := strings.ToLower(strings.TrimSpace(formatValue))
	switch format {
	case "json":
		return jsonutil.WriteIndented(w, rows)
	case "csv", "text":
		columns, err := parseControlColumns(columnsValue)
		if err != nil {
			return err
		}
		if format == "csv" {
			return writeControlListCSV(w, rows, columns, showHeaders)
		}
		return writeControlListText(w, rows, columns, showHeaders)
	default:
		return fmt.Errorf("invalid --format %q (use: text, json, csv)", formatValue)
	}
}

func runControlsListPacks(cmd *cobra.Command, listFormat string) error {
	items, err := packs.ListPacks()
	if err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(listFormat)) {
	case "json":
		return jsonutil.WriteIndented(cmd.OutOrStdout(), items)
	case "text":
		if len(items) == 0 {
			_, err = fmt.Fprintln(cmd.OutOrStdout(), "No packs found.")
			return err
		}
		for _, p := range items {
			if _, err = fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\n", p.Name, p.Description); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("invalid --format %q for --packs (use: text, json)", listFormat)
	}
}

func parseControlColumns(raw string) ([]string, error) {
	allowed := map[string]bool{"id": true, "name": true, "type": true, "severity": true, "domain": true}
	parts := strings.Split(raw, ",")
	cols := make([]string, 0, len(parts))
	seen := map[string]bool{}
	for _, p := range parts {
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
		return nil, errors.New("--columns must include at least one of: id,name,type,severity,domain")
	}
	return cols, nil
}

func controlField(row controlListRow, col string) string {
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

func writeControlListText(w io.Writer, rows []controlListRow, columns []string, showHeaders bool) error {
	if len(rows) == 0 {
		_, err := fmt.Fprintln(w, "No controls found.")
		return err
	}

	widths := controlColumnWidths(rows, columns)

	if err := writeControlRowsHeader(w, columns, widths, showHeaders); err != nil {
		return err
	}

	for _, r := range rows {
		if err := writeControlRowText(w, r, columns, widths); err != nil {
			return err
		}
	}
	return nil
}

func controlColumnWidths(rows []controlListRow, columns []string) []int {
	widths := make([]int, len(columns))
	for i, c := range columns {
		widths[i] = len(c)
	}
	for _, r := range rows {
		for i, c := range columns {
			v := controlField(r, c)
			if len(v) > widths[i] {
				widths[i] = len(v)
			}
		}
	}
	return widths
}

func writeControlRowsHeader(w io.Writer, columns []string, widths []int, showHeaders bool) error {
	if !showHeaders {
		return nil
	}
	return writeControlColumnValues(w, columns, widths)
}

func writeControlRowText(w io.Writer, row controlListRow, columns []string, widths []int) error {
	values := make([]string, 0, len(columns))
	for _, column := range columns {
		values = append(values, controlField(row, column))
	}
	return writeControlColumnValues(w, values, widths)
}

func writeControlColumnValues(w io.Writer, values []string, widths []int) error {
	for i, v := range values {
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

func writeControlListCSV(w io.Writer, rows []controlListRow, columns []string, showHeaders bool) error {
	cw := csv.NewWriter(w)
	if showHeaders {
		if err := cw.Write(columns); err != nil {
			return err
		}
	}
	for _, r := range rows {
		record := make([]string, 0, len(columns))
		for _, c := range columns {
			record = append(record, controlField(r, c))
		}
		if err := cw.Write(record); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func runControlsExplain(cmd *cobra.Command, args []string, controlsDir string) error {
	// Reuse existing explain implementation, but scoped under controls command.
	return diagnose.RunExplain(cmd, args, controlsDir, "text")
}
