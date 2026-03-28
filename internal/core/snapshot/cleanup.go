package snapshot

import (
	"context"
	"fmt"
)

// CleanerPort prunes stale observation snapshots.
type CleanerPort interface {
	CleanupSnapshots(ctx context.Context, req CleanupRequest) (CleanupResponse, error)
}

// CleanupDeps groups the port interfaces for the snapshot-cleanup use case.
type CleanupDeps struct {
	Cleaner CleanerPort
}

// Cleanup prunes stale observation snapshots by age.
func Cleanup(
	ctx context.Context,
	req CleanupRequest,
	deps CleanupDeps,
) (CleanupResponse, error) {
	if err := ctx.Err(); err != nil {
		return CleanupResponse{}, fmt.Errorf("snapshot-cleanup: %w", err)
	}

	if req.ObservationsDir == "" {
		return CleanupResponse{}, fmt.Errorf("snapshot-cleanup: observations directory is required")
	}
	if req.KeepMin < 0 {
		return CleanupResponse{}, fmt.Errorf("snapshot-cleanup: keep-min must be >= 0")
	}

	resp, err := deps.Cleaner.CleanupSnapshots(ctx, req)
	if err != nil {
		return CleanupResponse{}, fmt.Errorf("snapshot-cleanup: %w", err)
	}

	return resp, nil
}
