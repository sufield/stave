package artifacts

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/diagnose"
	"github.com/sufield/stave/internal/adapters/input/controls/builtin"
	packs "github.com/sufield/stave/internal/builtin/pack"
	predicates "github.com/sufield/stave/internal/builtin/predicate"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/metadata"
)

type controlsListFlagsType struct {
	listDir, explainDir               string
	listCols, listSort, listFormat    string
	listNoHdr, listBuiltIn, listPacks bool
}

var controlsListFlags controlsListFlagsType

type controlListRow struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Severity string `json:"severity,omitempty"`
	Domain   string `json:"domain,omitempty"`
}

var ControlsCmd = &cobra.Command{
	Use:     "controls",
	Aliases: []string{"controls"},
	Short:   "Work with control definitions",
	Long: `Controls groups commands for discovering and understanding control
definitions used by Stave.

Examples:
  stave controls list --controls ./controls
  stave controls explain CTL.S3.PUBLIC.001 --controls ./controls` + metadata.OfflineHelpSuffix,
	Args: cobra.NoArgs,
}

var controlsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List control IDs and names",
	Long: `List loads controls from a directory and prints concise metadata.

Examples:
  stave controls list --controls ./controls
  stave controls list --controls ./controls --format json
  stave controls list --controls ./controls --format csv --columns id,name` + metadata.OfflineHelpSuffix,
	Args:          cobra.NoArgs,
	RunE:          runControlsList,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var controlsExplainCmd = &cobra.Command{
	Use:   "explain <control-id>",
	Short: "Explain a specific control",
	Long: `Explain loads one control and prints matched fields, rule expectations,
and a minimal observation snippet.

Examples:
  stave controls explain CTL.S3.PUBLIC.001 --controls ./controls
  stave controls explain CTL.S3.PUBLIC.001 --controls ./controls --format json` + metadata.OfflineHelpSuffix,
	Args:          cobra.ExactArgs(1),
	RunE:          runControlsExplain,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var controlsAliasesCmd = &cobra.Command{
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

var controlsAliasExplainCmd = &cobra.Command{
	Use:   "alias-explain <alias>",
	Short: "Show expanded predicate for an alias",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		expanded, ok := predicates.Resolve(strings.TrimSpace(args[0]))
		if !ok {
			return fmt.Errorf("unknown alias %q (available: %s)", args[0], strings.Join(predicates.ListAliases(), ", "))
		}
		out := map[string]any{"alias": args[0], "expanded": expanded}
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	},
}

func init() {
	controlsListCmd.Flags().StringVarP(&controlsListFlags.listDir, "controls", "i", "controls/s3", "Path to control definitions directory")
	controlsListCmd.Flags().StringVarP(&controlsListFlags.listCols, "columns", "c", "id,name,type", "Comma-separated columns: id,name,type,severity,domain")
	controlsListCmd.Flags().StringVarP(&controlsListFlags.listSort, "sort", "s", "id", "Sort column: id,name,type,severity,domain")
	controlsListCmd.Flags().StringVarP(&controlsListFlags.listFormat, "format", "f", "text", "Output format: text, json, csv")
	controlsListCmd.Flags().BoolVar(&controlsListFlags.listNoHdr, "no-headers", false, "Hide headers for table/csv output")
	controlsListCmd.Flags().BoolVar(&controlsListFlags.listBuiltIn, "built-in", false, "List built-in embedded controls instead of filesystem")
	controlsListCmd.Flags().BoolVar(&controlsListFlags.listPacks, "packs", false, "List built-in control packs instead of controls")
	controlsExplainCmd.Flags().StringVar(&controlsListFlags.explainDir, "controls", "controls/s3", "Path to control definitions directory")

	ControlsCmd.AddCommand(controlsListCmd)
	ControlsCmd.AddCommand(controlsExplainCmd)
	ControlsCmd.AddCommand(controlsAliasesCmd)
	ControlsCmd.AddCommand(controlsAliasExplainCmd)
}

func runControlsList(cmd *cobra.Command, args []string) error {
	if controlsListFlags.listPacks {
		return runControlsListPacks(cmd)
	}
	controls, err := loadControlsForList()
	if err != nil {
		return err
	}
	rows := buildControlListRows(controls)
	if err := sortControlRows(rows, controlsListFlags.listSort); err != nil {
		return err
	}
	return writeControlRows(cmd.OutOrStdout(), rows, controlsListFlags.listFormat, controlsListFlags.listCols, !controlsListFlags.listNoHdr)
}

func loadControlsForList() ([]policy.ControlDefinition, error) {
	if controlsListFlags.listBuiltIn {
		controls, err := builtin.LoadAll(context.Background())
		if err != nil {
			return nil, fmt.Errorf("load built-in controls: %w", err)
		}
		return controls, nil
	}

	loader, err := cmdutil.NewControlRepository()
	if err != nil {
		return nil, fmt.Errorf("create control loader: %w", err)
	}
	controls, err := loader.LoadControls(context.Background(), strings.TrimSpace(controlsListFlags.listDir))
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
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(rows)
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

func runControlsListPacks(cmd *cobra.Command) error {
	items, err := packs.ListPacks()
	if err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(controlsListFlags.listFormat)) {
	case "json":
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(items)
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
		return fmt.Errorf("invalid --format %q for --packs (use: text, json)", controlsListFlags.listFormat)
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

func runControlsExplain(cmd *cobra.Command, args []string) error {
	// Reuse existing explain implementation, but scoped under controls command.
	return diagnose.RunExplain(cmd, args, controlsListFlags.explainDir, "text")
}
