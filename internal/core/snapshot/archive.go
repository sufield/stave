package snapshot

import (
	"context"
	"fmt"
)

// ArchiverPort archives stale observation snapshots.
type ArchiverPort interface {
	ArchiveSnapshots(ctx context.Context, req ArchiveRequest) (ArchiveResponse, error)
}

// ArchiveDeps groups the port interfaces for the snapshot-archive use case.
type ArchiveDeps struct {
	Archiver ArchiverPort
}

// Archive archives stale observation snapshots to a separate directory.
func Archive(
	ctx context.Context,
	req ArchiveRequest,
	deps ArchiveDeps,
) (ArchiveResponse, error) {
	if err := ctx.Err(); err != nil {
		return ArchiveResponse{}, fmt.Errorf("snapshot-archive: %w", err)
	}

	if req.ObservationsDir == "" {
		return ArchiveResponse{}, fmt.Errorf("snapshot-archive: observations directory is required")
	}
	if req.KeepMin < 0 {
		return ArchiveResponse{}, fmt.Errorf("snapshot-archive: keep-min must be >= 0")
	}

	resp, err := deps.Archiver.ArchiveSnapshots(ctx, req)
	if err != nil {
		return ArchiveResponse{}, fmt.Errorf("snapshot-archive: %w", err)
	}

	return resp, nil
}
