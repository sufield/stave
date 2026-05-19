// Package contract implements the `stave contract show` command —
// a single-source view of what an agent needs to produce a valid
// observation for an asset type: the per-asset JSON Schema, the
// property paths the catalog reads, control + chain counts per
// path, and (if any) the matching Steampipe mapping file.
//
// The command joins three sources that exist independently in the
// codebase:
//
//   - internal/contracts/schema/        — per-asset JSON Schemas
//   - internal/core/predindex/          — path -> controls / chains reverse index
//   - contracts/steampipe/<type>.yaml   — agent-side ingest mapping
//
// No new data is computed; everything is a runtime query against
// the embedded catalog and the workspace. Output changes when the
// catalog changes, without regeneration.
package contract

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/cli/ui"
	contractschema "github.com/sufield/stave/internal/contracts/schema"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predindex"
)

// Deps holds the adapter factories the command needs.
type Deps struct {
	NewCtlRepo     compose.CtlRepoFactory
	NewChainLoader compose.ChainLoaderFactory
}

type options struct {
	AssetType    string
	List         bool
	Format       string
	ControlsDir  string
	ChainsDir    string
	SteampipeDir string
}

// NewCmd constructs the `contract` parent command. Today it ships
// one subcommand (`show`); future siblings can add per-type lint or
// validate operations without reshuffling the parent shape.
func NewCmd(deps Deps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "contract",
		Short: "Inspect Stave's per-asset-type input contracts",
		Long: `Contract commands expose the data an agent needs to produce a valid
observation snapshot for a given asset type: the per-asset JSON Schema,
the property paths the catalog reads, control + chain counts per path,
and the Steampipe ingest mapping when one ships.

Subcommands:
  show     Show contract details for one asset type (or --list for all)
`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.AddCommand(newShowCmd(deps))
	return cmd
}

func newShowCmd(deps Deps) *cobra.Command {
	opts := &options{
		Format:       "text",
		ControlsDir:  "controls",
		ChainsDir:    "chains",
		SteampipeDir: "contracts/steampipe",
	}

	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show the agent-facing contract for an asset type",
		Long: `Show emits everything an agent needs to populate observations for
one asset type:

  - the per-asset JSON Schema path
  - the property paths the catalog reads, with type, control count,
    chain count, and a "required vs optional" hint
  - any Steampipe mapping under contracts/steampipe/

Use --list to enumerate every asset type with at least one
applicable_asset_types declaration in the catalog, showing whether
each has a schema and a Steampipe mapping.

Inputs:
  --asset-type T     Asset type to show (e.g. aws_s3_bucket)
  --list             List every asset type with controls (no --asset-type)
  --controls DIR     Control catalog (default: controls)
  --chains DIR       Chain catalog (default: chains)
  --steampipe DIR    Directory of Steampipe mappings (default: contracts/steampipe)
  --format F         text (default) | json

Exit codes:
  0   Success
  2   Invalid input (missing flag, unknown asset type)
  4   Internal error (catalog load failure)
`,
		Example: `  # Detailed view for one type
  stave contract show --asset-type aws_s3_bucket

  # All types with at-a-glance schema + mapping presence
  stave contract show --list

  # Machine-readable
  stave contract show --asset-type aws_iam_role --format json`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.Context(), cmd.OutOrStdout(), opts, deps)
		},
	}

	cmd.Flags().StringVar(&opts.AssetType, "asset-type", "", "asset type to inspect (e.g. aws_s3_bucket)")
	cmd.Flags().BoolVar(&opts.List, "list", false, "list every asset type with controls")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "text", "output format: text | json")
	cmd.Flags().StringVarP(&opts.ControlsDir, "controls", "i", "controls", "control catalog directory")
	cmd.Flags().StringVar(&opts.ChainsDir, "chains", "chains", "chain catalog directory")
	cmd.Flags().StringVar(&opts.SteampipeDir, "steampipe", "contracts/steampipe", "Steampipe mapping directory")

	return cmd
}

func run(ctx context.Context, w io.Writer, opts *options, deps Deps) error {
	if !opts.List && opts.AssetType == "" {
		return &ui.UserError{Err: errors.New("either --asset-type or --list is required")}
	}
	if opts.List && opts.AssetType != "" {
		return &ui.UserError{Err: errors.New("--asset-type and --list are mutually exclusive")}
	}
	renderer, rendErr := NewRenderer(opts.Format)
	if rendErr != nil {
		return &ui.UserError{Err: rendErr}
	}

	controls, err := compose.LoadControlsFrom(ctx, deps.NewCtlRepo, opts.ControlsDir)
	if err != nil {
		return fmt.Errorf("load controls: %w", err)
	}
	chains, err := compose.LoadChainDefinitions(ctx, deps.NewChainLoader, opts.ChainsDir)
	if err != nil {
		// Missing chains dir is non-fatal — contract output is
		// still meaningful, chain counts just become zero.
		var notFound interface{ NotFound() bool }
		if !errors.As(err, &notFound) || !notFound.NotFound() {
			return fmt.Errorf("load chains: %w", err)
		}
		chains = nil
	}
	idx := predindex.Build(controls, chains)

	if opts.List {
		return renderList(w, renderer, idx, opts.SteampipeDir)
	}
	return renderType(w, renderer, opts.AssetType, idx, opts.SteampipeDir)
}

// pathRow is the per-path row that ships in both text and JSON
// output for a single asset type.
type pathRow struct {
	Path             string `json:"path"`
	ControlsCount    int    `json:"controls_count"`
	ChainsCount      int    `json:"chains_count"`
	MaxSeverity      string `json:"max_severity,omitempty"`
	IsIntentProperty bool   `json:"is_intent_property"`
}

type typeReport struct {
	AssetType        string    `json:"asset_type"`
	HasSchema        bool      `json:"has_schema"`
	SchemaPath       string    `json:"schema_path,omitempty"`
	ControlsCount    int       `json:"controls_count"`
	ChainsCount      int       `json:"chains_count"`
	PropertyPaths    []pathRow `json:"property_paths"`
	SteampipeMapping string    `json:"steampipe_mapping,omitempty"`
}

func renderType(w io.Writer, renderer Renderer, assetType string, idx predindex.Index, steampipeDir string) error {
	at := kernel.AssetType(assetType)
	paths := idx.TypeToPaths[at]
	if len(paths) == 0 {
		return &ui.UserError{Err: fmt.Errorf("no controls declare applicable_asset_types: [%s]", assetType)}
	}

	rows := make([]pathRow, 0, len(paths))
	chainSet := map[kernel.ChainID]struct{}{}
	controlSet := map[kernel.ControlID]struct{}{}
	for _, p := range paths {
		ctls := idx.PathToControls[p]
		chs := idx.PathToChains[p]
		for _, c := range ctls {
			controlSet[c] = struct{}{}
		}
		for _, ch := range chs {
			chainSet[ch] = struct{}{}
		}
		rows = append(rows, pathRow{
			Path:             p,
			ControlsCount:    len(ctls),
			ChainsCount:      len(chs),
			MaxSeverity:      idx.PathMaxSeverity[p].String(),
			IsIntentProperty: isIntentProperty(p),
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].ChainsCount != rows[j].ChainsCount {
			return rows[i].ChainsCount > rows[j].ChainsCount
		}
		if rows[i].ControlsCount != rows[j].ControlsCount {
			return rows[i].ControlsCount > rows[j].ControlsCount
		}
		return rows[i].Path < rows[j].Path
	})

	report := typeReport{
		AssetType:     assetType,
		PropertyPaths: rows,
		ControlsCount: len(controlSet),
		ChainsCount:   len(chainSet),
	}
	if _, err := contractschema.AssetTypeSchema(assetType); err == nil {
		report.HasSchema = true
		report.SchemaPath = fmt.Sprintf("schemas/observation/v1/asset-types/%s.schema.json", assetType)
	}
	if mapping := findSteampipeMapping(steampipeDir, assetType); mapping != "" {
		report.SteampipeMapping = mapping
	}

	return renderer.Render(w, report)
}

type listRow struct {
	AssetType        string `json:"asset_type"`
	HasSchema        bool   `json:"has_schema"`
	ControlsCount    int    `json:"controls_count"`
	ChainsCount      int    `json:"chains_count"`
	SteampipeMapping bool   `json:"steampipe_mapping"`
}

type listReport struct {
	Types         []listRow `json:"types"`
	TotalTypes    int       `json:"total_types"`
	WithSchema    int       `json:"with_schema"`
	WithSteampipe int       `json:"with_steampipe"`
}

func renderList(w io.Writer, renderer Renderer, idx predindex.Index, steampipeDir string) error {
	types := make([]string, 0, len(idx.TypeToPaths))
	for t := range idx.TypeToPaths {
		types = append(types, string(t))
	}
	sort.Strings(types)

	rows := make([]listRow, 0, len(types))
	withSchema := 0
	withSteampipe := 0
	for _, t := range types {
		row := listRow{AssetType: t}
		if _, err := contractschema.AssetTypeSchema(t); err == nil {
			row.HasSchema = true
			withSchema++
		}
		paths := idx.TypeToPaths[kernel.AssetType(t)]
		ctlSet := map[kernel.ControlID]struct{}{}
		chSet := map[kernel.ChainID]struct{}{}
		for _, p := range paths {
			for _, c := range idx.PathToControls[p] {
				ctlSet[c] = struct{}{}
			}
			for _, c := range idx.PathToChains[p] {
				chSet[c] = struct{}{}
			}
		}
		row.ControlsCount = len(ctlSet)
		row.ChainsCount = len(chSet)
		if findSteampipeMapping(steampipeDir, t) != "" {
			row.SteampipeMapping = true
			withSteampipe++
		}
		rows = append(rows, row)
	}
	report := listReport{
		Types:         rows,
		TotalTypes:    len(rows),
		WithSchema:    withSchema,
		WithSteampipe: withSteampipe,
	}

	return renderer.Render(w, report)
}

// findSteampipeMapping returns the (workspace-relative) path of the
// matching contracts/steampipe/<type>.yaml when it exists, or the
// empty string when no mapping is present.
func findSteampipeMapping(dir, assetType string) string {
	if dir == "" {
		return ""
	}
	candidate := filepath.Join(dir, assetType+".yaml")
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return ""
}

// isIntentProperty returns true when the path looks like
// operator-declared intent (tags, role-type labels, environment
// markers). Matches the heuristic the gaps command uses for the
// same purpose so output stays consistent across commands.
func isIntentProperty(path string) bool {
	low := strings.ToLower(path)
	switch {
	case strings.Contains(low, ".tags."):
		return true
	case strings.HasSuffix(low, ".data_classification"):
		return true
	case strings.HasSuffix(low, ".environment"):
		return true
	case strings.HasSuffix(low, ".role_type"):
		return true
	}
	return false
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func writeTypeText(w io.Writer, r typeReport) error {
	fmt.Fprintf(w, "Contract: %s\n", r.AssetType)
	if r.HasSchema {
		fmt.Fprintf(w, "Schema:   %s\n", r.SchemaPath)
	} else {
		fmt.Fprintf(w, "Schema:   (none — no per-asset schema registered)\n")
	}
	fmt.Fprintf(w, "Controls: %d | Chains: %d\n\n", r.ControlsCount, r.ChainsCount)

	if len(r.PropertyPaths) == 0 {
		fmt.Fprintln(w, "(no property paths declared)")
		return nil
	}

	fmt.Fprintln(w, "Property paths (catalog reads these — sorted by chain unlock, then control unlock):")
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "  PATH\tCONTROLS\tCHAINS\tSEVERITY\tNOTE")
	fmt.Fprintln(tw, "  ────\t────────\t──────\t────────\t────")
	for _, p := range r.PropertyPaths {
		note := ""
		if p.IsIntentProperty {
			note = "intent"
		}
		fmt.Fprintf(tw, "  %s\t%d\t%d\t%s\t%s\n",
			strings.TrimPrefix(p.Path, "properties."),
			p.ControlsCount, p.ChainsCount, p.MaxSeverity, note)
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	if r.SteampipeMapping != "" {
		fmt.Fprintf(w, "\nSteampipe mapping: %s\n", r.SteampipeMapping)
	} else {
		fmt.Fprintln(w, "\nSteampipe mapping: (none — author one at contracts/steampipe/"+r.AssetType+".yaml)")
	}
	return nil
}

func writeListText(w io.Writer, r listReport) error {
	fmt.Fprintf(w, "Asset types with controls: %d (schema: %d, steampipe mapping: %d)\n\n",
		r.TotalTypes, r.WithSchema, r.WithSteampipe)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "  TYPE\tSCHEMA\tCONTROLS\tCHAINS\tMAPPING")
	fmt.Fprintln(tw, "  ────\t──────\t────────\t──────\t───────")
	for _, t := range r.Types {
		schema := "-"
		if t.HasSchema {
			schema = "yes"
		}
		mapping := "-"
		if t.SteampipeMapping {
			mapping = "steampipe"
		}
		fmt.Fprintf(tw, "  %s\t%s\t%d\t%d\t%s\n",
			t.AssetType, schema, t.ControlsCount, t.ChainsCount, mapping)
	}
	return tw.Flush()
}
