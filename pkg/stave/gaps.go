package stave

import (
	"context"
	"errors"
	"fmt"

	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/app/gaps"
	"github.com/sufield/stave/internal/core/capabilities"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// GapReport is a field-level coverage analysis: for each observation
// property absent from the supplied snapshots, the controls it would
// unlock if populated, ranked by impact.
type GapReport = gaps.Report

// FieldGap is one entry in [GapReport.Gaps] — a single absent
// (asset_type, property_path) along with what it blocks and the
// remediation hint. Aliased into the facade so a renderer that walks
// the report does not need to import the internal analyzer package.
type FieldGap = gaps.FieldGap

// GapsOptions configures [Gaps]. SnapshotsDir is required; the rest
// have sensible defaults.
//
// ControlsDir empty selects the embedded builtin catalog. Set it to a
// YAML control directory to evaluate gaps against a fork.
//
// ChainsDir empty omits chain-blocking analysis; the per-gap rollup
// still reports controls_blocked. Set it to load chain YAML and
// populate chains_blocked; a missing directory is non-fatal and
// reduces to the empty-chains case.
//
// TopN <= 0 applies the analyzer default.
type GapsOptions struct {
	SnapshotsDir string
	ControlsDir  string
	ChainsDir    string
	TopN         int
}

// Gaps analyzes which observation fields the snapshots in
// opts.SnapshotsDir are missing and which controls (and, when
// opts.ChainsDir is set, which chains) each absent field would
// unlock if populated. See [GapsOptions] for the knobs.
//
// The return value's TopN summary considers the top opts.TopN gaps
// by impact; the full ranked list is in GapReport.Gaps.
func Gaps(ctx context.Context, opts GapsOptions) (*GapReport, error) {
	if opts.SnapshotsDir == "" {
		return nil, errors.New("stave.Gaps: SnapshotsDir is required")
	}
	controls, err := loadControlsOrBuiltin(ctx, opts.ControlsDir)
	if err != nil {
		return nil, err
	}
	snaps, err := loadSnapshots(ctx, opts.SnapshotsDir)
	if err != nil {
		return nil, err
	}
	chains, err := loadChainsOptional(opts.ChainsDir)
	if err != nil {
		return nil, err
	}
	report := gaps.Analyze(controls, chains, snaps, opts.TopN)
	return &report, nil
}

// loadControlsOrBuiltin mirrors [resolveControls]'s dispatch but
// returns fully-loaded controls (no ControlRepository needed because
// there is no overdue/SLA path here). Empty dir → builtin; set dir
// → YAML loader. Shared by [Gaps] and [Readiness].
func loadControlsOrBuiltin(ctx context.Context, dir string) ([]policy.ControlDefinition, error) {
	if dir == "" {
		return builtinControls()
	}
	preloaded, loader, err := resolveControls(dir)
	if err != nil {
		return nil, err
	}
	if preloaded != nil {
		return preloaded, nil
	}
	controls, err := loader.LoadControls(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("load controls from %s: %w", dir, err)
	}
	return controls, nil
}

// loadChainsOptional loads chain YAML from dir using the builtin
// capability registry. Empty dir or a directory-not-found error
// returns no chains — chain analysis is optional, mirroring the
// "missing chains dir is non-fatal" behaviour cmd/gaps and
// cmd/readiness used to implement themselves. Shared by [Gaps] and
// [Readiness].
func loadChainsOptional(dir string) ([]policy.ChainDefinition, error) {
	if dir == "" {
		return nil, nil
	}
	chains, err := ctlyaml.LoadChains(dir, capabilities.Builtin())
	if err != nil {
		var notFound interface{ NotFound() bool }
		if errors.As(err, &notFound) && notFound.NotFound() {
			return nil, nil
		}
		return nil, fmt.Errorf("load chains from %s: %w", dir, err)
	}
	return chains, nil
}
