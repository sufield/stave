package graph

import (
	"context"
	"fmt"
	"io"
	"strings"

	"maps"
	"slices"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/dircheck"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// Format represents a validated graph output format.
type Format string

const (
	FormatDot  Format = "dot"
	FormatJSON Format = "json"
)

// ParseFormat validates and returns a Format value.
func ParseFormat(s string) (Format, error) {
	normalized := Format(ui.NormalizeToken(s))
	switch normalized {
	case FormatDot, FormatJSON:
		return normalized, nil
	default:
		return "", ui.EnumError("--format", s, []string{string(FormatDot), string(FormatJSON)})
	}
}

// config holds the validated parameters for graph generation.
type config struct {
	ControlsDir     string
	ObservationsDir string
	Format          Format
	AllowUnknown    bool
	Sanitizer       kernel.Sanitizer
	Stdout          io.Writer
	PredicateEval   policy.PredicateEval
}

// Runner orchestrates loading assets and generating coverage graphs.
type Runner struct {
	LoadControls  compose.ControlLoaderFunc
	LoadSnapshots compose.SnapshotLoader
}

// NewRunner initializes a graph runner.
func NewRunner(loadControls compose.ControlLoaderFunc, loadSnapshots compose.SnapshotLoader) *Runner {
	return &Runner{LoadControls: loadControls, LoadSnapshots: loadSnapshots}
}

// CoverageEdge represents a single control→asset coverage relationship.
type CoverageEdge struct {
	ControlID kernel.ControlID `json:"control_id"`
	AssetID   asset.ID         `json:"asset_id"`
}

// CoverageResult holds the complete coverage graph data.
type CoverageResult struct {
	Controls        []kernel.ControlID `json:"controls"`
	Assets          []asset.ID         `json:"assets"`
	Edges           []CoverageEdge     `json:"edges"`
	UncoveredAssets []asset.ID         `json:"uncovered_assets"`
}

// Run validates inputs, loads artifacts, builds the coverage graph, and writes it.
func (r *Runner) Run(ctx context.Context, cfg config) error {
	if err := dircheck.ValidateFlagDir("--controls", cfg.ControlsDir, "", nil, nil); err != nil {
		return &ui.UserError{Err: fmt.Errorf("invalid controls directory: %w", err)}
	}
	if err := dircheck.ValidateFlagDir("--observations", cfg.ObservationsDir, "", nil, nil); err != nil {
		return &ui.UserError{Err: fmt.Errorf("invalid observations directory: %w", err)}
	}

	controls, latestSnapshot, err := r.loadArtifacts(ctx, cfg.ControlsDir, cfg.ObservationsDir)
	if err != nil {
		return fmt.Errorf("loading artifacts: %w", err)
	}
	result := buildResult(controls, latestSnapshot, cfg.PredicateEval)
	return writeResult(cfg.Stdout, cfg.Format, result, cfg.Sanitizer)
}

func (r *Runner) loadArtifacts(ctx context.Context, controlsDir, observationsDir string) ([]policy.ControlDefinition, asset.Snapshot, error) {
	controls, err := r.LoadControls(ctx, controlsDir)
	if err != nil {
		return nil, asset.Snapshot{}, fmt.Errorf("load controls: %w", err)
	}
	snapshots, err := r.LoadSnapshots(ctx, observationsDir)
	if err != nil {
		return nil, asset.Snapshot{}, fmt.Errorf("load snapshots: %w", err)
	}
	latest, latestErr := compose.LatestSnapshot(snapshots)
	if latestErr != nil {
		return nil, asset.Snapshot{}, fmt.Errorf("%w: no observation snapshots found in %s", latestErr, observationsDir)
	}
	return controls, latest, nil
}

func buildResult(controls []policy.ControlDefinition, latest asset.Snapshot, eval policy.PredicateEval) CoverageResult {
	assetMap, assetIDs := coverageAssets(latest.Assets)
	controlIDs := coverageControlIDs(controls)
	edges, covered := CoverageEdges(controls, assetMap, assetIDs, latest.Identities, eval)
	return CoverageResult{
		Controls:        controlIDs,
		Assets:          assetIDs,
		Edges:           edges,
		UncoveredAssets: uncoveredAssets(assetIDs, covered),
	}
}

func coverageAssets(assets []asset.Asset) (map[asset.ID]asset.Asset, []asset.ID) {
	assetMap := make(map[asset.ID]asset.Asset, len(assets))
	for _, a := range assets {
		assetMap[a.ID] = a
	}
	if len(assetMap) == 0 {
		return assetMap, nil
	}
	return assetMap, slices.Sorted(maps.Keys(assetMap))
}

func coverageControlIDs(controls []policy.ControlDefinition) []kernel.ControlID {
	ids := make([]kernel.ControlID, len(controls))
	for i, ctl := range controls {
		ids[i] = ctl.ID
	}
	return ids
}

func CoverageEdges(
	controls []policy.ControlDefinition,
	assetMap map[asset.ID]asset.Asset,
	assetIDs []asset.ID,
	identities []asset.CloudIdentity,
	eval policy.PredicateEval,
) ([]CoverageEdge, map[asset.ID]bool) {
	edges := make([]CoverageEdge, 0, len(assetIDs))
	coveredAssets := make(map[asset.ID]bool, len(assetIDs))
	if eval == nil {
		return edges, coveredAssets
	}
	for i := range controls {
		ctl := &controls[i]
		for _, rid := range assetIDs {
			unsafe, err := eval(*ctl, assetMap[rid], identities)
			if err != nil || !unsafe {
				continue
			}
			edges = append(edges, CoverageEdge{ControlID: ctl.ID, AssetID: rid})
			coveredAssets[rid] = true
		}
	}
	return edges, coveredAssets
}

func uncoveredAssets(assetIDs []asset.ID, coveredAssets map[asset.ID]bool) []asset.ID {
	out := make([]asset.ID, 0)
	for _, rid := range assetIDs {
		if !coveredAssets[rid] {
			out = append(out, rid)
		}
	}
	return out
}

func writeResult(w io.Writer, format Format, result CoverageResult, sanitizer kernel.Sanitizer) error {
	switch format {
	case FormatDot:
		return writeDOT(w, result, sanitizer)
	case FormatJSON:
		return writeJSON(w, result, sanitizer)
	default:
		return nil
	}
}

func writeDOT(w io.Writer, result CoverageResult, sanitizer kernel.Sanitizer) error {
	uncoveredSet := make(map[asset.ID]bool)
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
		fmt.Fprintf(w, "    %s [style=filled, fillcolor=lightblue];\n", dotQuote(id.String()))
	}
	fmt.Fprintln(w, "  }")
	fmt.Fprintln(w)

	// Assets cluster
	fmt.Fprintln(w, "  subgraph cluster_assets {")
	fmt.Fprintln(w, `    label="Assets";`)
	for _, rid := range result.Assets {
		displayID := sanitizer.ID(rid.String())
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
		assetDisplay := sanitizer.ID(edge.AssetID.String())
		fmt.Fprintf(w, "  %s -> %s;\n", dotQuote(edge.ControlID.String()), dotQuote(assetDisplay))
	}

	fmt.Fprintln(w, "}")
	return nil
}

// dotQuote wraps a string in double quotes for DOT format, escaping inner quotes.
func dotQuote(s string) string {
	escaped := strings.ReplaceAll(s, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\\"`)
	return `"` + escaped + `"`
}

func writeJSON(w io.Writer, result CoverageResult, sanitizer kernel.Sanitizer) error {
	for i, rid := range result.Assets {
		result.Assets[i] = asset.ID(sanitizer.ID(rid.String()))
	}
	for i, edge := range result.Edges {
		result.Edges[i].AssetID = asset.ID(sanitizer.ID(edge.AssetID.String()))
	}
	for i, rid := range result.UncoveredAssets {
		result.UncoveredAssets[i] = asset.ID(sanitizer.ID(rid.String()))
	}

	return jsonutil.WriteIndented(w, result)
}
