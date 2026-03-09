package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	ctlyaml "github.com/sufield/stave/internal/adapters/input/controls/yaml"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/sanitize"
)

type options struct {
	ControlsDir     string
	ObservationsDir string
	Format          string
	AllowUnknown    bool
}

func defaultOptions() *options {
	allowUnknown := projconfig.ResolveAllowUnknownInputDefault()
	return &options{
		ControlsDir:     "controls/s3",
		ObservationsDir: "observations",
		Format:          "dot",
		AllowUnknown:    allowUnknown,
	}
}

func (o *options) bindFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&o.ControlsDir, "controls", "i", o.ControlsDir, "Path to control definitions directory")
	cmd.Flags().StringVarP(&o.ObservationsDir, "observations", "o", o.ObservationsDir, "Path to observation snapshots directory")
	cmd.Flags().StringVarP(&o.Format, "format", "f", o.Format, "Output format: dot or json")
	cmd.Flags().BoolVar(&o.AllowUnknown, "allow-unknown-input", o.AllowUnknown, cmdutil.WithDynamicDefaultHelp("Allow observations with unknown or missing source types"))
}

// coverageEdge represents a single control→asset coverage relationship.
type coverageEdge struct {
	ControlID string `json:"control_id"`
	AssetID   string `json:"asset_id"`
}

// coverageResult holds the complete coverage graph data.
type coverageResult struct {
	Controls        []string       `json:"controls"`
	Assets          []string       `json:"assets"`
	Edges           []coverageEdge `json:"edges"`
	UncoveredAssets []string       `json:"uncovered_assets"`
}

func runCoverage(cmd *cobra.Command, opts *options) error {
	input, err := prepareInput(opts)
	if err != nil {
		return err
	}
	controls, latestSnapshot, err := loadArtifacts(cmd.Context(), input)
	if err != nil {
		return err
	}
	result := buildResult(controls, latestSnapshot)
	return writeResult(cmd.OutOrStdout(), input.format, result, cmdutil.GetSanitizer(cmd))
}

type input struct {
	controlsDir     string
	observationsDir string
	format          string
}

func prepareInput(opts *options) (input, error) {
	controlsDir := fsutil.CleanUserPath(opts.ControlsDir)
	observationsDir := fsutil.CleanUserPath(opts.ObservationsDir)
	if err := cmdutil.ValidateDir("--controls", controlsDir, nil); err != nil {
		return input{}, err
	}
	if err := cmdutil.ValidateDir("--observations", observationsDir, nil); err != nil {
		return input{}, err
	}
	if err := validateFormat(opts.Format); err != nil {
		return input{}, err
	}
	return input{controlsDir: controlsDir, observationsDir: observationsDir, format: opts.Format}, nil
}

func validateFormat(format string) error {
	switch format {
	case "dot", "json":
		return nil
	default:
		return fmt.Errorf("invalid --format %q (use dot or json)", format)
	}
}

func loadArtifacts(ctx context.Context, input input) ([]policy.ControlDefinition, asset.Snapshot, error) {
	controls, err := compose.LoadControls(ctx, input.controlsDir)
	if err != nil {
		return nil, asset.Snapshot{}, err
	}
	snapshots, err := compose.LoadSnapshots(ctx, input.observationsDir)
	if err != nil {
		return nil, asset.Snapshot{}, err
	}
	if len(snapshots) == 0 {
		return nil, asset.Snapshot{}, fmt.Errorf("no observation snapshots found in %s", input.observationsDir)
	}
	return controls, asset.LatestSnapshot(snapshots), nil
}

func buildResult(controls []policy.ControlDefinition, latest asset.Snapshot) coverageResult {
	assetMap, assetIDs := coverageAssets(latest.Assets)
	controlIDs := coverageControlIDs(controls)
	edges, covered := coverageEdges(controls, assetMap, assetIDs, latest.Identities)
	return coverageResult{
		Controls:        controlIDs,
		Assets:          assetIDs,
		Edges:           edges,
		UncoveredAssets: uncoveredAssets(assetIDs, covered),
	}
}

func coverageAssets(assets []asset.Asset) (map[string]asset.Asset, []string) {
	assetMap := make(map[string]asset.Asset, len(assets))
	for _, a := range assets {
		assetMap[a.ID.String()] = a
	}
	assetIDs := make([]string, 0, len(assetMap))
	for id := range assetMap {
		assetIDs = append(assetIDs, id)
	}
	slices.Sort(assetIDs)
	return assetMap, assetIDs
}

func coverageControlIDs(controls []policy.ControlDefinition) []string {
	controlIDs := make([]string, 0, len(controls))
	for _, ctl := range controls {
		controlIDs = append(controlIDs, ctl.ID.String())
	}
	return controlIDs
}

func coverageEdges(
	controls []policy.ControlDefinition,
	assetMap map[string]asset.Asset,
	assetIDs []string,
	identities []asset.CloudIdentity,
) ([]coverageEdge, map[string]bool) {
	edges := make([]coverageEdge, 0)
	coveredAssets := make(map[string]bool, len(assetIDs))
	for i := range controls {
		ctl := &controls[i]
		for _, rid := range assetIDs {
			evalCtx := policy.NewAssetEvalContextWithIdentities(assetMap[rid], policy.ControlParams(ctl.Params), identities)
			evalCtx.PredicateParser = ctlyaml.YAMLPredicateParser
			if !ctl.UnsafePredicate.EvaluateWithContext(evalCtx) {
				continue
			}
			edges = append(edges, coverageEdge{ControlID: ctl.ID.String(), AssetID: rid})
			coveredAssets[rid] = true
		}
	}
	return edges, coveredAssets
}

func uncoveredAssets(assetIDs []string, coveredAssets map[string]bool) []string {
	uncovered := make([]string, 0)
	for _, rid := range assetIDs {
		if !coveredAssets[rid] {
			uncovered = append(uncovered, rid)
		}
	}
	return uncovered
}

func writeResult(w io.Writer, format string, result coverageResult, sanitizer *sanitize.Sanitizer) error {
	switch format {
	case "dot":
		return writeDOT(w, result, sanitizer)
	case "json":
		return writeJSON(w, result, sanitizer)
	default:
		return nil
	}
}

func writeDOT(w io.Writer, result coverageResult, sanitizer *sanitize.Sanitizer) error {
	uncoveredSet := make(map[string]bool)
	for _, r := range result.UncoveredAssets {
		uncoveredSet[r] = true
	}

	fmt.Fprintln(w, "digraph StaveCoverage {")
	fmt.Fprintln(w, `  rankdir="LR";`)
	fmt.Fprintln(w, `  node [shape=box, style=rounded];`)
	fmt.Fprintln(w)

	// Controls cluster
	fmt.Fprintln(w, "  subgraph cluster_controls {")
	fmt.Fprintln(w, `    label="Controls";`)
	fmt.Fprintln(w, `    style="filled";`)
	fmt.Fprintln(w, `    color="lightgrey";`)
	for _, id := range result.Controls {
		fmt.Fprintf(w, "    %s [style=filled, fillcolor=lightblue];\n", dotQuote(id))
	}
	fmt.Fprintln(w, "  }")
	fmt.Fprintln(w)

	// Assets cluster
	fmt.Fprintln(w, "  subgraph cluster_assets {")
	fmt.Fprintln(w, `    label="Assets";`)
	for _, rid := range result.Assets {
		displayID := string(sanitizer.Asset(asset.ID(rid)))
		if uncoveredSet[rid] {
			fmt.Fprintf(w, "    %s [style=filled, fillcolor=lightyellow];\n", dotQuote(displayID))
		} else {
			fmt.Fprintf(w, "    %s;\n", dotQuote(displayID))
		}
	}
	fmt.Fprintln(w, "  }")
	fmt.Fprintln(w)

	// Edges
	for _, edge := range result.Edges {
		assetDisplay := string(sanitizer.Asset(asset.ID(edge.AssetID)))
		fmt.Fprintf(w, "  %s -> %s;\n", dotQuote(edge.ControlID), dotQuote(assetDisplay))
	}

	fmt.Fprintln(w, "}")
	return nil
}

// dotQuote wraps a string in double quotes for DOT format, escaping inner quotes.
func dotQuote(s string) string {
	escaped := strings.ReplaceAll(s, `\\`, `\\\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\\"`)
	return `"` + escaped + `"`
}

func writeJSON(w io.Writer, result coverageResult, sanitizer *sanitize.Sanitizer) error {
	for i, rid := range result.Assets {
		result.Assets[i] = string(sanitizer.Asset(asset.ID(rid)))
	}
	for i, edge := range result.Edges {
		result.Edges[i].AssetID = string(sanitizer.Asset(asset.ID(edge.AssetID)))
	}
	for i, rid := range result.UncoveredAssets {
		result.UncoveredAssets[i] = string(sanitizer.Asset(asset.ID(rid)))
	}

	if result.Edges == nil {
		result.Edges = []coverageEdge{}
	}
	if result.UncoveredAssets == nil {
		result.UncoveredAssets = []string{}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}
