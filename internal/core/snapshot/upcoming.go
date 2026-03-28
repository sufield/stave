package snapshot

import (
	"context"
	"fmt"
)

// UpcomingComputerPort computes upcoming action items for unsafe assets.
type UpcomingComputerPort interface {
	ComputeUpcoming(ctx context.Context, req UpcomingRequest) (any, error)
}

// UpcomingDeps groups the port interfaces for the snapshot upcoming use case.
type UpcomingDeps struct {
	Computer UpcomingComputerPort
}

// Upcoming computes upcoming action items for currently unsafe assets.
func Upcoming(
	ctx context.Context,
	req UpcomingRequest,
	deps UpcomingDeps,
) (UpcomingResponse, error) {
	if err := ctx.Err(); err != nil {
		return UpcomingResponse{}, fmt.Errorf("snapshot_upcoming: %w", err)
	}

	data, err := deps.Computer.ComputeUpcoming(ctx, req)
	if err != nil {
		return UpcomingResponse{}, fmt.Errorf("snapshot_upcoming: %w", err)
	}

	return UpcomingResponse{ItemsData: data}, nil
}
