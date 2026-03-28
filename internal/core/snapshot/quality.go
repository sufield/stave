package snapshot

import (
	"context"
	"fmt"
)

// QualityCheckerPort checks snapshot quality for operational readiness.
type QualityCheckerPort interface {
	CheckQuality(ctx context.Context, req QualityRequest) (QualityResponse, error)
}

// QualityDeps groups the port interfaces for the snapshot-quality use case.
type QualityDeps struct {
	Checker QualityCheckerPort
}

// Quality checks the observation timeline for operational readiness.
func Quality(
	ctx context.Context,
	req QualityRequest,
	deps QualityDeps,
) (QualityResponse, error) {
	if err := ctx.Err(); err != nil {
		return QualityResponse{}, fmt.Errorf("snapshot-quality: %w", err)
	}

	if req.ObservationsDir == "" {
		return QualityResponse{}, fmt.Errorf("snapshot-quality: observations directory is required")
	}
	if req.MinSnapshots < 1 {
		return QualityResponse{}, fmt.Errorf("snapshot-quality: min-snapshots must be >= 1")
	}

	resp, err := deps.Checker.CheckQuality(ctx, req)
	if err != nil {
		return QualityResponse{}, fmt.Errorf("snapshot-quality: %w", err)
	}

	return resp, nil
}
