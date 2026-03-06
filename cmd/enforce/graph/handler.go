package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	ctlyaml "github.com/sufield/stave/internal/adapters/input/controls/yaml"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// assetSanitizer sanitizes asset identifiers in output.
type assetSanitizer interface {
	Asset(asset.ID) asset.ID
}

type options struct {
	ControlsDir     string
	ObservationsDir string
	Format          string
	AllowUnknown    bool
}

func defaultOptions() *options {
	allowUnknown := cmdutil.ResolveAllowUnknownInputDefault()
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

// coverageEdge represents a single control→resource coverage relationship.
type coverageEdge struct {
	ControlID string `json:"control_id"`
	AssetID   string `json:"asset_id"`
}

// coverageResult holds the complete coverage graph data.
type coverageResult struct {
	Controls           []string       `json:"controls"`
	Resources          []string       `json:"resources"`
	Edges              []coverageEdge `json:"edges"`
	UncoveredResources []string       `json:"uncovered_resources"`
}

func runCoverage(cmd *cobra.Command, opts *options) error {
	input, err := prepareInput(opts)
	if err != nil {
		return err
	}
	controls, latestSnapshot, err := loadArtifacts(input)
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
	if err := ensureDir("--controls", controlsDir); err != nil {
		return input{}, err
	}
	if err := ensureDir("--observations", observationsDir); err != nil {
		return input{}, err
	}
	if err := validateFormat(opts.Format); err != nil {
		return input{}, err
	}
	return input{controlsDir: controlsDir, observationsDir: observationsDir, format: opts.Format}, nil
}

func ensureDir(flagName, path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return ui.DirectoryAccessError(flagName, path, err, nil)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s must be a directory: %s", flagName, path)
	}
	return nil
}

func validateFormat(format string) error {
	switch format {
	case "dot", "json":
		return nil
	default:
		return fmt.Errorf("invalid --format %q (use dot or json)", format)
	}
}

func loadArtifacts(input input) ([]policy.ControlDefinition, asset.Snapshot, error) {
	ctx := context.Background()
	controls, err := loadControls(ctx, input.controlsDir)
	if err != nil {
		return nil, asset.Snapshot{}, err
	}
	snapshots, err := loadSnapshots(ctx, input.observationsDir)
	if err != nil {
		return nil, asset.Snapshot{}, err
	}
	return controls, latestSnapshot(snapshots), nil
}

func loadControls(ctx context.Context, controlsDir string) ([]policy.ControlDefinition, error) {
	ctlLoader, err := cmdutil.NewControlRepository()
	if err != nil {
		return nil, fmt.Errorf("create control loader: %w", err)
	}
	controls, err := ctlLoader.LoadControls(ctx, controlsDir)
	if err != nil {
		return nil, fmt.Errorf("load controls: %w", err)
	}
	return controls, nil
}

func loadSnapshots(ctx context.Context, observationsDir string) ([]asset.Snapshot, error) {
	obsLoader, err := cmdutil.NewObservationRepository()
	if err != nil {
		return nil, fmt.Errorf("create observation loader: %w", err)
	}
	result, err := obsLoader.LoadSnapshots(ctx, observationsDir)
	if err != nil {
		return nil, fmt.Errorf("load observations: %w", err)
	}
	if len(result.Snapshots) == 0 {
		return nil, fmt.Errorf("no observation snapshots found in %s", observationsDir)
	}
	return result.Snapshots, nil
}

func latestSnapshot(snapshots []asset.Snapshot) asset.Snapshot {
	latest := snapshots[0]
	for _, snapshot := range snapshots[1:] {
		if snapshot.CapturedAt.After(latest.CapturedAt) {
			latest = snapshot
		}
	}
	return latest
}

func buildResult(controls []policy.ControlDefinition, latest asset.Snapshot) coverageResult {
	resourceMap, resourceIDs := coverageResources(latest.Resources)
	controlIDs := coverageControlIDs(controls)
	edges, covered := coverageEdges(controls, resourceMap, resourceIDs, latest.Identities)
	return coverageResult{
		Controls:           controlIDs,
		Resources:          resourceIDs,
		Edges:              edges,
		UncoveredResources: coverageUncovered(resourceIDs, covered),
	}
}

func coverageResources(resources []asset.Asset) (map[string]asset.Asset, []string) {
	resourceMap := make(map[string]asset.Asset, len(resources))
	for _, resource := range resources {
		resourceMap[resource.ID.String()] = resource
	}
	resourceIDs := make([]string, 0, len(resourceMap))
	for id := range resourceMap {
		resourceIDs = append(resourceIDs, id)
	}
	slices.Sort(resourceIDs)
	return resourceMap, resourceIDs
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
	resourceMap map[string]asset.Asset,
	resourceIDs []string,
	identities []asset.CloudIdentity,
) ([]coverageEdge, map[string]bool) {
	edges := make([]coverageEdge, 0)
	coveredResources := make(map[string]bool, len(resourceIDs))
	for i := range controls {
		ctl := &controls[i]
		for _, rid := range resourceIDs {
			evalCtx := policy.NewResourceEvalContextWithIdentities(resourceMap[rid], policy.ControlParams(ctl.Params), identities)
			evalCtx.PredicateParser = ctlyaml.YAMLPredicateParser
			if !ctl.UnsafePredicate.EvaluateWithContext(evalCtx) {
				continue
			}
			edges = append(edges, coverageEdge{ControlID: ctl.ID.String(), AssetID: rid})
			coveredResources[rid] = true
		}
	}
	return edges, coveredResources
}

func coverageUncovered(resourceIDs []string, coveredResources map[string]bool) []string {
	uncovered := make([]string, 0)
	for _, rid := range resourceIDs {
		if !coveredResources[rid] {
			uncovered = append(uncovered, rid)
		}
	}
	return uncovered
}

func writeResult(w io.Writer, format string, result coverageResult, sanitizer assetSanitizer) error {
	switch format {
	case "dot":
		return writeDOT(w, result, sanitizer)
	case "json":
		return writeJSON(w, result, sanitizer)
	default:
		return nil
	}
}

func writeDOT(w io.Writer, result coverageResult, sanitizer assetSanitizer) error {
	uncoveredSet := make(map[string]bool)
	for _, r := range result.UncoveredResources {
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

	// Resources cluster
	fmt.Fprintln(w, "  subgraph cluster_resources {")
	fmt.Fprintln(w, `    label="Resources";`)
	for _, rid := range result.Resources {
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
		resourceDisplay := string(sanitizer.Asset(asset.ID(edge.AssetID)))
		fmt.Fprintf(w, "  %s -> %s;\n", dotQuote(edge.ControlID), dotQuote(resourceDisplay))
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

func writeJSON(w io.Writer, result coverageResult, sanitizer assetSanitizer) error {
	for i, rid := range result.Resources {
		result.Resources[i] = string(sanitizer.Asset(asset.ID(rid)))
	}
	for i, edge := range result.Edges {
		result.Edges[i].AssetID = string(sanitizer.Asset(asset.ID(edge.AssetID)))
	}
	for i, rid := range result.UncoveredResources {
		result.UncoveredResources[i] = string(sanitizer.Asset(asset.ID(rid)))
	}

	if result.Edges == nil {
		result.Edges = []coverageEdge{}
	}
	if result.UncoveredResources == nil {
		result.UncoveredResources = []string{}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}
