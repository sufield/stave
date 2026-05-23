package stave

import (
	"context"
	"errors"

	"github.com/sufield/stave/internal/app/readiness"
)

// ReadinessReport forecasts what the catalog can and cannot evaluate
// against a snapshot: observed vs. catalog asset types, per-control
// fire/blocked counts, a readiness score, and a ranked action plan
// of the fields that would unblock the most controls. Renderers that
// iterate ObservedTypes/CatalogTypes can use [AssetType] (already
// aliased in ids.go) for the map keys.
type ReadinessReport = readiness.Report

// ReadinessOptions configures [Readiness]. SnapshotsDir is required;
// the rest have sensible defaults.
//
// ControlsDir empty selects the embedded builtin catalog. Set it to
// a YAML control directory to forecast readiness against a fork.
//
// ChainsDir empty omits chain readiness; the per-control forecast
// still runs. Set it to load chain YAML and populate the chain
// effectiveness block; a missing directory is non-fatal and reduces
// to the no-chains case.
//
// TopN <= 0 applies the analyzer default for the action-plan rollup.
type ReadinessOptions struct {
	SnapshotsDir string
	ControlsDir  string
	ChainsDir    string
	TopN         int
}

// Readiness reports how much of the catalog can fire against the
// snapshots in opts.SnapshotsDir — which asset types are present,
// how many controls/chains are evaluable vs. blocked, and what to
// collect next. See [ReadinessOptions] for the knobs.
//
// Framework-scoped readiness belongs to [Compliance].
func Readiness(ctx context.Context, opts ReadinessOptions) (*ReadinessReport, error) {
	if opts.SnapshotsDir == "" {
		return nil, errors.New("stave.Readiness: SnapshotsDir is required")
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
	report := readiness.Analyze(controls, chains, snaps, opts.TopN)
	return &report, nil
}
