package usecases

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/core/domain"
)

// SnapshotDeltaComputerPort computes the observation delta between the
// latest two snapshots in a directory, applying optional filters.
type SnapshotDeltaComputerPort interface {
	ComputeDelta(ctx context.Context, observationsDir string, changeTypes, assetTypes []string, assetID string) (any, error)
}

// SnapshotDiffDeps groups the port interfaces for the snapshot diff use case.
type SnapshotDiffDeps struct {
	DeltaComputer SnapshotDeltaComputerPort
}

// SnapshotDiff computes the observation delta between the latest two snapshots.
func SnapshotDiff(
	ctx context.Context,
	req domain.SnapshotDiffRequest,
	deps SnapshotDiffDeps,
) (domain.SnapshotDiffResponse, error) {
	if err := ctx.Err(); err != nil {
		return domain.SnapshotDiffResponse{}, fmt.Errorf("snapshot_diff: %w", err)
	}

	delta, err := deps.DeltaComputer.ComputeDelta(ctx, req.ObservationsDir, req.ChangeTypes, req.AssetTypes, req.AssetID)
	if err != nil {
		return domain.SnapshotDiffResponse{}, fmt.Errorf("snapshot_diff: %w", err)
	}

	return domain.SnapshotDiffResponse{DeltaData: delta}, nil
}
