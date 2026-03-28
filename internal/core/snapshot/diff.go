package snapshot

import (
	"context"
	"fmt"
)

// DeltaComputerPort computes the observation delta between the
// latest two snapshots in a directory, applying optional filters.
type DeltaComputerPort interface {
	ComputeDelta(ctx context.Context, observationsDir string, changeTypes, assetTypes []string, assetID string) (any, error)
}

// DiffDeps groups the port interfaces for the snapshot diff use case.
type DiffDeps struct {
	DeltaComputer DeltaComputerPort
}

// Diff computes the observation delta between the latest two snapshots.
func Diff(
	ctx context.Context,
	req DiffRequest,
	deps DiffDeps,
) (DiffResponse, error) {
	if err := ctx.Err(); err != nil {
		return DiffResponse{}, fmt.Errorf("snapshot_diff: %w", err)
	}

	delta, err := deps.DeltaComputer.ComputeDelta(ctx, req.ObservationsDir, req.ChangeTypes, req.AssetTypes, req.AssetID)
	if err != nil {
		return DiffResponse{}, fmt.Errorf("snapshot_diff: %w", err)
	}

	return DiffResponse{DeltaData: delta}, nil
}
