package stave

import (
	"context"
	"errors"

	"github.com/sufield/stave/pkg/stave/internal/applycmd"
)

// StandardRequest is the parsed input for the default `apply` (standard
// evaluation) path. Every field is a primitive or path string — the command
// holds no internal evaluation/config types.
type StandardRequest = applycmd.StandardRequest

// StandardResult is the rendered outcome of a standard evaluation: the report
// bytes (stdout), stderr-bound warnings, and the gating signals (security
// state, gate decision, SLA flags) the command maps to its exit code.
type StandardResult = applycmd.StandardResult

// EvaluateStandard runs the default `apply` pipeline — load config, evaluate
// via the applycore engine, annotate owner/reachability context, render to
// bytes (or the new-only diff), and compute the gating decision. The facade
// self-constructs every adapter from the request.
//
// Input errors (missing --history-dir, bad --new-since) wrap [ErrInvalidInput]
// (the command maps them to exit 2); evaluation/render errors stay plain
// (exit 4, decorated command-side).
func EvaluateStandard(ctx context.Context, req StandardRequest) (StandardResult, error) {
	res, err := applycmd.EvaluateStandard(ctx, req)
	if err != nil {
		if errors.Is(err, applycmd.ErrInvalidInput) {
			return StandardResult{}, asInvalidInput(err)
		}
		return StandardResult{}, err //nolint:wrapcheck // engine already wrapped; preserve exit 4.
	}
	return res, nil
}
