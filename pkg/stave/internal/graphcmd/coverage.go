// Package graphcmd is the engine behind `stave graph coverage` and
// `stave graph export` (and pkg/stave.CoverageGraph / ExportAssessmentGraph).
// The commands keep only flag wiring, directory validation, file reads, and
// the output write; the load → build → render logic lives here.
package graphcmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/adapters/observations"
	"github.com/sufield/stave/internal/adapters/predicate"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/sanitize"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// InputError marks a user-input failure (unknown format, bad assessment
// JSON). The pkg/stave facade unwraps it and re-wraps with
// stave.ErrInvalidInput so the CLI exits 2; load/compute/render failures
// stay plain (exit 4).
type InputError struct{ Err error }

// Error implements error.
func (e *InputError) Error() string { return e.Err.Error() }

// Unwrap exposes the wrapped cause.
func (e *InputError) Unwrap() error { return e.Err }

// Format represents a validated coverage-graph output format.
type Format string

// Supported coverage output formats.
const (
	FormatDot  Format = "dot"
	FormatJSON Format = "json"
)

// ParseFormat validates and returns a Format value (case-insensitive,
// trimmed). An unrecognised value wraps [InputError] (exit 2).
func ParseFormat(s string) (Format, error) {
	normalized := Format(strings.ToLower(strings.TrimSpace(s)))
	switch normalized {
	case FormatDot, FormatJSON:
		return normalized, nil
	default:
		return "", &InputError{fmt.Errorf("invalid --format %q (expected: dot | json)", s)}
	}
}

// CoverageConfig parameterizes [RunCoverage]. It mirrors the `stave graph
// coverage` flags plus the global --sanitize / --path-mode settings.
type CoverageConfig struct {
	ControlsDir     string
	ObservationsDir string
	Format          string // dot | json
	SanitizeIDs     bool
	PathMode        string
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

// RunCoverage loads the controls + the latest snapshot, builds the
// control→asset coverage graph, and renders it as DOT or JSON.
func RunCoverage(ctx context.Context, cfg CoverageConfig) ([]byte, error) {
	format, err := ParseFormat(cfg.Format)
	if err != nil {
		return nil, err
	}

	controls, latest, err := loadCoverageArtifacts(ctx, cfg.ControlsDir, cfg.ObservationsDir)
	if err != nil {
		return nil, fmt.Errorf("loading artifacts: %w", err)
	}

	// NOTE: the predicate evaluator is intentionally nil here, preserving the
	// pre-facade command behavior verbatim (config.PredicateEval was never
	// wired, so coverage edges are not currently computed and every asset is
	// reported uncovered — locked by TestBuildResult / TestCoverageEdges_NilEval).
	result := buildResult(controls, latest, nil)

	sanitizer := sanitize.Policy{SanitizeIDs: cfg.SanitizeIDs, PathMode: sanitize.PathMode(cfg.PathMode)}.NewSanitizer()

	var buf strings.Builder
	if err := writeResult(&buf, format, result, sanitizer); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

func loadCoverageArtifacts(ctx context.Context, controlsDir, observationsDir string) ([]policy.ControlDefinition, asset.Snapshot, error) {
	repo := ctlyaml.NewControlLoader(ctlyaml.WithAliasResolver(predicate.ResolverFunc()))
	controls, err := repo.LoadControls(ctx, controlsDir)
	if err != nil {
		return nil, asset.Snapshot{}, fmt.Errorf("load controls: %w", err)
	}
	res, err := observations.NewObservationLoader().LoadSnapshots(ctx, observationsDir)
	if err != nil {
		return nil, asset.Snapshot{}, fmt.Errorf("load snapshots: %w", err)
	}
	latest, latestErr := latestSnapshot(res.Snapshots)
	if latestErr != nil {
		return nil, asset.Snapshot{}, fmt.Errorf("%w: no observation snapshots found in %s", latestErr, observationsDir)
	}
	return controls, latest, nil
}

func latestSnapshot(snapshots []asset.Snapshot) (asset.Snapshot, error) {
	if len(snapshots) == 0 {
		return asset.Snapshot{}, errors.New("no observation snapshots")
	}
	latest := snapshots[0]
	for _, s := range snapshots[1:] {
		if s.CapturedAt.After(latest.CapturedAt) {
			latest = s
		}
	}
	return latest, nil
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
	for i := range controls {
		ctl := &controls[i]
		ids[i] = ctl.ID
	}
	return ids
}

// CoverageEdges computes edges between controls and assets where the control's
// predicate matches the asset, returning the edges and a set of covered asset IDs.
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
	r, err := NewCoverageRenderer(format)
	if err != nil {
		//nolint:nilerr // unknown Format is a boundary-validated no-op: ParseFormat rejects unknown CLI input upstream, and TestWriteResult_Unknown pins this swallow.
		return nil
	}
	if err := r.Render(w, result, sanitizer); err != nil {
		return fmt.Errorf("render output: %w", err)
	}
	return nil
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

	if err := jsonutil.WriteIndented(w, result); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}
