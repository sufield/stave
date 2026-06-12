package stave

import (
	"context"
	"errors"
	"fmt"

	"github.com/sufield/stave/pkg/stave/internal/trendcmd"
)

// TrendConfig parameterizes [TrendReport]. Mirrors the `stave trend` flags.
type TrendConfig = trendcmd.TrendConfig

// TrendPredictConfig parameterizes [PredictReadiness].
type TrendPredictConfig = trendcmd.PredictConfig

// TrendForecastConfig parameterizes [ForecastPosture].
type TrendForecastConfig = trendcmd.ForecastConfig

// TrendOscillationConfig parameterizes [ClassifyOscillation].
type TrendOscillationConfig = trendcmd.OscillationConfig

// TrendReport computes the compliance posture-trend report across a sequence
// of assessment files and renders it (table | json | openmetrics |
// executive-summary), returning the rendered bytes plus per-file load
// warnings (for stderr). All failures stay plain (exit 4) — matching the
// pre-facade `stave trend`, which never wrapped its errors. It is the library
// entry point behind `stave trend`.
func TrendReport(ctx context.Context, cfg TrendConfig) (output []byte, warnings []string, err error) {
	return trendcmd.TrendReport(ctx, cfg) //nolint:wrapcheck // engine already wrapped; preserve exit 4 for every error.
}

// PredictReadiness estimates the compliance-readiness achievement date and
// renders it (text | json). Returns bytes + load warnings. An unknown format
// wraps [ErrInvalidInput] (exit 2, matching the subcommand's ui.UserError);
// other failures stay plain (exit 4). Library entry point behind
// `stave trend predict`.
func PredictReadiness(ctx context.Context, cfg TrendPredictConfig) (output []byte, warnings []string, err error) {
	return mapTrendInputErr(trendcmd.PredictReadiness(ctx, cfg))
}

// ForecastPosture projects the posture-score trajectory and renders it
// (table | json). Returns bytes + load warnings. Unknown format wraps
// [ErrInvalidInput] (exit 2); other failures stay plain (exit 4). Library
// entry point behind `stave trend forecast`.
func ForecastPosture(ctx context.Context, cfg TrendForecastConfig) (output []byte, warnings []string, err error) {
	return mapTrendInputErr(trendcmd.ForecastPosture(ctx, cfg))
}

// ClassifyOscillation classifies violation oscillation patterns and renders
// them (table | json). Returns bytes + load warnings. Unknown format wraps
// [ErrInvalidInput] (exit 2); other failures stay plain (exit 4). Library
// entry point behind `stave trend oscillation`.
func ClassifyOscillation(ctx context.Context, cfg TrendOscillationConfig) (output []byte, warnings []string, err error) {
	return mapTrendInputErr(trendcmd.ClassifyOscillation(ctx, cfg))
}

// mapTrendInputErr re-wraps a trendcmd.InputError (unknown --format on a
// subcommand) with ErrInvalidInput so the CLI exits 2; everything else passes
// through plain (exit 4).
func mapTrendInputErr(output []byte, warnings []string, err error) ([]byte, []string, error) {
	if err != nil {
		var ie *trendcmd.InputError
		if errors.As(err, &ie) {
			return nil, warnings, fmt.Errorf("%w: %w", ie.Err, ErrInvalidInput)
		}
		return nil, warnings, err //nolint:wrapcheck // engine already wrapped; preserve exit 4.
	}
	return output, warnings, nil
}
