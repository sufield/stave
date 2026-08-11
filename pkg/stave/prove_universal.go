package stave

import (
	"context"
	"errors"
	"fmt"

	"github.com/sufield/stave/internal/core/universals"
)

// ProveUniversalConfig configures a universal evaluation run.
type ProveUniversalConfig struct {
	SnapshotsDir  string
	FormulaDir    string
	GroundingPath string
}

// UniversalSummary is the facade result type for universal evaluation.
type UniversalSummary = universals.Summary

// UniversalResult is a single universal's evaluation result.
type UniversalResult = universals.Result

// ProveUniversal evaluates all universal statements against observations
// via Z3 subprocess. Does not require CGO — the Z3 binary must be on PATH.
func ProveUniversal(_ context.Context, cfg ProveUniversalConfig) (*UniversalSummary, error) {
	if cfg.SnapshotsDir == "" {
		return nil, errors.New("prove universal: --observations is required")
	}
	if cfg.FormulaDir == "" {
		return nil, errors.New("prove universal: --formulas is required (no embedded formulas available)")
	}

	assets, err := universals.LoadAssetsFromDir(cfg.SnapshotsDir)
	if err != nil {
		return nil, fmt.Errorf("prove universal: %w", err)
	}

	result, err := universals.EvaluateAll(universals.EvaluateConfig{
		FormulaDir:    cfg.FormulaDir,
		GroundingPath: cfg.GroundingPath,
		Assets:        assets,
	})
	if err != nil {
		return nil, fmt.Errorf("prove universal: %w", err)
	}
	return result, nil
}
