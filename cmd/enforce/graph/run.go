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

// ControlLoaderFunc loads controls from a directory.
type ControlLoaderFunc func(ctx context.Context, dir string) ([]policy.ControlDefinition, error)

// Runner orchestrates loading assets and generating coverage graphs.
type Runner struct {
	LoadControls  ControlLoaderFunc
	LoadSnapshots compose.SnapshotLoader
}

// NewRunner initializes a graph runner.
func NewRunner(loadControls ControlLoaderFunc, loadSnapshots compose.SnapshotLoader) *Runner {
	return &Runner{LoadControls: loadControls, LoadSnapshots: loadSnapshots}
}

// CoverageEdge represents a single control→asset coverage relationship.
type CoverageEdge struct {
	ControlID string `json:"control_id"`
	AssetID   string `json:"asset_id"`
}

// CoverageResult holds the complete coverage graph data.
type CoverageResult struct {
	Controls        []string       `json:"controls"`
	Assets          []string       `json:"assets"`
	Edges           []CoverageEdge `json:"edges"`
	UncoveredAssets []string       `json:"uncovered_assets"`
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

func coverageAssets(assets []asset.Asset) (map[string]asset.Asset, []string) {
	assetMap := make(map[string]asset.Asset, len(assets))
	for _, a := range assets {
		assetMap[a.ID.String()] = a
	}
	if len(assetMap) == 0 {
		return assetMap, nil
	}
	return assetMap, slices.Sorted(maps.Keys(assetMap))
}

func coverageControlIDs(controls []policy.ControlDefinition) []string {
	ids := make([]string, len(controls))
	for i, ctl := range controls {
		ids[i] = ctl.ID.String()
	}
	return ids
}

func CoverageEdges(
	controls []policy.ControlDefinition,
	assetMap map[string]asset.Asset,
	assetIDs []string,
	identities []asset.CloudIdentity,
	eval policy.PredicateEval,
) ([]CoverageEdge, map[string]bool) {
	edges := make([]CoverageEdge, 0, len(assetIDs))
	coveredAssets := make(map[string]bool, len(assetIDs))
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
			edges = append(edges, CoverageEdge{ControlID: ctl.ID.String(), AssetID: rid})
			coveredAssets[rid] = true
		}
	}
	return edges, coveredAssets
}

func uncoveredAssets(assetIDs []string, coveredAssets map[string]bool) []string {
	out := make([]string, 0)
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
		displayID := sanitizer.ID(rid)
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
		assetDisplay := sanitizer.ID(edge.AssetID)
		fmt.Fprintf(w, "  %s -> %s;\n", dotQuote(edge.ControlID), dotQuote(assetDisplay))
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
		result.Assets[i] = sanitizer.ID(rid)
	}
	for i, edge := range result.Edges {
		result.Edges[i].AssetID = sanitizer.ID(edge.AssetID)
	}
	for i, rid := range result.UncoveredAssets {
		result.UncoveredAssets[i] = sanitizer.ID(rid)
	}

	return jsonutil.WriteIndented(w, result)
}
