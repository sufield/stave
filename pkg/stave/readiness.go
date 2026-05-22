package stave

import (
	"context"
	"errors"

	"github.com/sufield/stave/internal/app/readiness"
)

// ReadinessReport forecasts what the catalog can and cannot evaluate
// against a snapshot: observed vs. catalog asset types, per-control
// fire/blocked counts, a readiness score, and a ranked action plan
// of the fields that would unblock the most controls.
type ReadinessReport = readiness.Report

// Readiness reports how much of the embedded builtin catalog can fire
// against the snapshots in snapshotsDir — which asset types are
// present, how many controls are evaluable vs. blocked, and what to
// collect next. topN bounds the action plan (<= 0 applies the
// analyzer default).
//
// Chain readiness is not forecast — chains require a chains
// directory, which this offline accessor does not load. Framework-
// scoped readiness belongs to [Compliance].
func Readiness(ctx context.Context, snapshotsDir string, topN int) (*ReadinessReport, error) {
	if snapshotsDir == "" {
		return nil, errors.New("stave.Readiness: snapshotsDir is required")
	}
	controls, err := builtinControls()
	if err != nil {
		return nil, err
	}
	snaps, err := loadSnapshots(ctx, snapshotsDir)
	if err != nil {
		return nil, err
	}
	report := readiness.Analyze(controls, nil, snaps, topN)
	return &report, nil
}
