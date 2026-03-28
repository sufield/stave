package snapshot

import (
	"context"
	"fmt"
)

// HygieneReporterPort generates a snapshot lifecycle hygiene report.
type HygieneReporterPort interface {
	GenerateHygieneReport(ctx context.Context, req HygieneRequest) (HygieneResponse, error)
}

// HygieneDeps groups the port interfaces for the snapshot-hygiene use case.
type HygieneDeps struct {
	Reporter HygieneReporterPort
}

// Hygiene generates a weekly snapshot lifecycle hygiene report.
func Hygiene(
	ctx context.Context,
	req HygieneRequest,
	deps HygieneDeps,
) (HygieneResponse, error) {
	if err := ctx.Err(); err != nil {
		return HygieneResponse{}, fmt.Errorf("snapshot-hygiene: %w", err)
	}

	if req.ObservationsDir == "" {
		return HygieneResponse{}, fmt.Errorf("snapshot-hygiene: observations directory is required")
	}

	resp, err := deps.Reporter.GenerateHygieneReport(ctx, req)
	if err != nil {
		return HygieneResponse{}, fmt.Errorf("snapshot-hygiene: %w", err)
	}

	return resp, nil
}
