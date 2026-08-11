package stave

import (
	"context"
	"errors"
	"fmt"

	"github.com/sufield/stave/internal/core/evaluation"
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
// (exit 4, decorated command-side). Attestation failures wrap
// [ErrAttestationFailed] (exit 6).
func EvaluateStandard(ctx context.Context, req StandardRequest) (StandardResult, error) {
	if err := verifyAttestationPreEval(&req); err != nil {
		return StandardResult{}, err
	}

	res, err := applycmd.EvaluateStandard(ctx, req)
	if err != nil {
		if errors.Is(err, applycmd.ErrInvalidInput) {
			return StandardResult{}, asInvalidInput(err)
		}
		return StandardResult{}, err //nolint:wrapcheck // engine already wrapped; preserve exit 4.
	}
	return res, nil
}

// verifyAttestationPreEval runs attestation verification before evaluation
// when --verify-key or --require-signed is set. It populates
// req.AttestationStatus for downstream output annotation.
func verifyAttestationPreEval(req *StandardRequest) error {
	if req.VerifyKey == "" {
		return nil
	}
	if req.ObservationsDir == "-" {
		return fmt.Errorf("--verify-key is not supported with stdin observations: %w", ErrInvalidInput)
	}

	pubKey, err := LoadPublicKeyPEM(req.VerifyKey)
	if err != nil {
		return fmt.Errorf("load attestation key: %w: %w", err, ErrInvalidInput)
	}

	status, verifyErr := VerifyObservationsDir(req.ObservationsDir, pubKey)
	if verifyErr != nil {
		if status != nil && status.Status == evaluation.AttestationFailed {
			return fmt.Errorf("%w: %w", verifyErr, ErrAttestationFailed)
		}
		return fmt.Errorf("attestation check: %w", verifyErr)
	}

	if req.RequireSigned && status.Status == evaluation.AttestationUnsigned {
		return fmt.Errorf("--require-signed: observations are not attested; sign with `stave attest sign`: %w", ErrAttestationFailed)
	}

	req.AttestationStatus = status
	return nil
}
