package graph

import (
	"context"
	"fmt"
	"io"
	"strings"

	"maps"
	"slices"

	"github.com/samber/lo"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/dircheck"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/pkg/jsonutil"
	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
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

// Config holds the validated parameters for graph generation.
type Config struct {
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
	Provider *compose.Provider
}

// NewRunner initializes a graph runner.
func NewRunner(p *compose.Provider) *Runner {
	return &Runner{Provider: p}
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

// Run validates inputs, loads artifacts, builds the coverage graph, and writes it.
func (r *Runner) Run(ctx context.Context, cfg Config) error {
	if err := dircheck.ValidateFlagDir("--controls", cfg.ControlsDir, "", nil, nil); err != nil {
		return err
	}
	if err := dircheck.ValidateFlagDir("--observations", cfg.ObservationsDir, "", nil, nil); err != nil {
		return err
	}

	controls, latestSnapshot, err := r.loadArtifacts(ctx, cfg.ControlsDir, cfg.ObservationsDir)
	if err != nil {
		return err
	}
	result := buildResult(controls, latestSnapshot, cfg.PredicateEval)
	return writeResult(cfg.Stdout, cfg.Format, result, cfg.Sanitizer)
}

func (r *Runner) loadArtifacts(ctx context.Context, controlsDir, observationsDir string) ([]policy.ControlDefinition, asset.Snapshot, error) {
	controls, err := compose.LoadControls(ctx, r.Provider, controlsDir)
	if err != nil {
		return nil, asset.Snapshot{}, err
	}
	snapshots, err := compose.LoadSnapshots(ctx, r.Provider, observationsDir)
	if err != nil {
		return nil, asset.Snapshot{}, err
	}
	if len(snapshots) == 0 {
		return nil, asset.Snapshot{}, fmt.Errorf("%w: no observation snapshots found in %s", appeval.ErrNoSnapshots, observationsDir)
	}
	latest := snapshots[0]
	for _, s := range snapshots[1:] {
		if s.CapturedAt.After(latest.CapturedAt) {
			latest = s
		}
	}
	return controls, latest, nil
}

func buildResult(controls []policy.ControlDefinition, latest asset.Snapshot, eval policy.PredicateEval) coverageResult {
	assetMap, assetIDs := coverageAssets(latest.Assets)
	controlIDs := coverageControlIDs(controls)
	edges, covered := coverageEdges(controls, assetMap, assetIDs, latest.Identities, eval)
	return coverageResult{
		Controls:        controlIDs,
		Assets:          assetIDs,
		Edges:           edges,
		UncoveredAssets: uncoveredAssets(assetIDs, covered),
	}
}

func coverageAssets(assets []asset.Asset) (map[string]asset.Asset, []string) {
	assetMap := lo.KeyBy(assets, func(a asset.Asset) string { return a.ID.String() })
	if len(assetMap) == 0 {
		return assetMap, nil
	}
	return assetMap, slices.Sorted(maps.Keys(assetMap))
}

func coverageControlIDs(controls []policy.ControlDefinition) []string {
	return lo.Map(controls, func(ctl policy.ControlDefinition, _ int) string { return ctl.ID.String() })
}

func coverageEdges(
	controls []policy.ControlDefinition,
	assetMap map[string]asset.Asset,
	assetIDs []string,
	identities []asset.CloudIdentity,
	eval policy.PredicateEval,
) ([]coverageEdge, map[string]bool) {
	edges := make([]coverageEdge, 0)
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
			edges = append(edges, coverageEdge{ControlID: ctl.ID.String(), AssetID: rid})
			coveredAssets[rid] = true
		}
	}
	return edges, coveredAssets
}

func uncoveredAssets(assetIDs []string, coveredAssets map[string]bool) []string {
	return lo.Reject(assetIDs, func(rid string, _ int) bool { return coveredAssets[rid] })
}

func writeResult(w io.Writer, format Format, result coverageResult, sanitizer kernel.Sanitizer) error {
	switch format {
	case FormatDot:
		return writeDOT(w, result, sanitizer)
	case FormatJSON:
		return writeJSON(w, result, sanitizer)
	default:
		return nil
	}
}

func writeDOT(w io.Writer, result coverageResult, sanitizer kernel.Sanitizer) error {
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

func writeJSON(w io.Writer, result coverageResult, sanitizer kernel.Sanitizer) error {
	for i, rid := range result.Assets {
		result.Assets[i] = sanitizer.ID(rid)
	}
	for i, edge := range result.Edges {
		result.Edges[i].AssetID = sanitizer.ID(edge.AssetID)
	}
	for i, rid := range result.UncoveredAssets {
		result.UncoveredAssets[i] = sanitizer.ID(rid)
	}

	if result.Edges == nil {
		result.Edges = []coverageEdge{}
	}
	if result.UncoveredAssets == nil {
		result.UncoveredAssets = []string{}
	}

	return jsonutil.WriteIndented(w, result)
}
