package stave

import (
	"context"
	"errors"

	"github.com/sufield/stave/internal/app/gaps"
)

// GapReport is a field-level coverage analysis: for each observation
// property absent from the supplied snapshots, the controls it would
// unlock if populated, ranked by impact.
type GapReport = gaps.Report

// Gaps analyzes which observation fields the snapshots in
// snapshotsDir are missing and what built-in controls each absent
// field would unlock. topN bounds how many gaps the summary's
// "unblocked by top N" rollup considers (<= 0 applies the analyzer
// default).
//
// The analysis runs against the embedded builtin catalog. Chain-
// blocking gaps are not reported — they require a chains directory,
// which this offline accessor does not load.
func Gaps(ctx context.Context, snapshotsDir string, topN int) (*GapReport, error) {
	if snapshotsDir == "" {
		return nil, errors.New("stave.Gaps: snapshotsDir is required")
	}
	controls, err := builtinControls()
	if err != nil {
		return nil, err
	}
	snaps, err := loadSnapshots(ctx, snapshotsDir)
	if err != nil {
		return nil, err
	}
	report := gaps.Analyze(controls, nil, snaps, topN)
	return &report, nil
}
