package usecases

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/core/domain"
)

// SnapshotUpcomingComputerPort computes upcoming action items for unsafe assets.
type SnapshotUpcomingComputerPort interface {
	ComputeUpcoming(ctx context.Context, req domain.SnapshotUpcomingRequest) (any, error)
}

// SnapshotUpcomingDeps groups the port interfaces for the snapshot upcoming use case.
type SnapshotUpcomingDeps struct {
	Computer SnapshotUpcomingComputerPort
}

// SnapshotUpcoming computes upcoming action items for currently unsafe assets.
func SnapshotUpcoming(
	ctx context.Context,
	req domain.SnapshotUpcomingRequest,
	deps SnapshotUpcomingDeps,
) (domain.SnapshotUpcomingResponse, error) {
	if err := ctx.Err(); err != nil {
		return domain.SnapshotUpcomingResponse{}, fmt.Errorf("snapshot_upcoming: %w", err)
	}

	data, err := deps.Computer.ComputeUpcoming(ctx, req)
	if err != nil {
		return domain.SnapshotUpcomingResponse{}, fmt.Errorf("snapshot_upcoming: %w", err)
	}

	return domain.SnapshotUpcomingResponse{ItemsData: data}, nil
}
