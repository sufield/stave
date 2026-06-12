package stave

import (
	"context"
	"errors"
	"fmt"

	"github.com/sufield/stave/pkg/stave/internal/applycmd"
)

// ProfileRequest is the parsed input for `apply --profile`.
type ProfileRequest = applycmd.ProfileRequest

// ProfileResult is the rendered outcome of a profile evaluation: the report
// bytes (stdout), stderr-bound warnings + diagnose hint, and the violation
// signal the command maps to its exit code.
type ProfileResult = applycmd.ProfileResult

// EvaluateProfile runs the `apply --profile` pipeline: load the observation
// bundle, filter by scope, load the requested profiles' controls, evaluate,
// enrich, and render to bytes. The facade self-constructs the CEL evaluator,
// control loader, finding marshaler, sanitizer, and clock from the request.
//
// Input errors (bad --input / --now) wrap [ErrInvalidInput] (the command maps
// them to exit 2); evaluation/render errors stay plain (exit 4).
func EvaluateProfile(ctx context.Context, req ProfileRequest) (ProfileResult, error) {
	res, err := applycmd.EvaluateProfile(ctx, req)
	if err != nil {
		if errors.Is(err, applycmd.ErrInvalidProfileInput) {
			return ProfileResult{}, fmt.Errorf("%w: %w", err, ErrInvalidInput)
		}
		return ProfileResult{}, err //nolint:wrapcheck // engine already wrapped; preserve exit 4.
	}
	return res, nil
}
