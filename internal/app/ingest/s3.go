package ingest

import (
	"context"
	"fmt"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
)

// S3IngestExtractRequest captures the minimum data required to extract
// observations from an S3 snapshot directory.
type S3IngestExtractRequest struct {
	Context     context.Context
	SnapshotDir string
	Now         time.Time
	Extract     func(ctx context.Context, snapshotDir string, now time.Time) ([]asset.Snapshot, error)
}

// ExtractS3Snapshots transforms raw snapshot files into normalized observations.
func ExtractS3Snapshots(req S3IngestExtractRequest) ([]asset.Snapshot, error) {
	if req.Extract == nil {
		return nil, fmt.Errorf("extract function is required")
	}
	ctx := req.Context
	if ctx == nil {
		ctx = context.Background()
	}

	snapshots, err := req.Extract(ctx, req.SnapshotDir, req.Now)
	if err != nil {
		return nil, fmt.Errorf("extract S3 observations: %w", err)
	}
	return snapshots, nil
}

// SnapshotScrubber sanitizes snapshot data before persistence.
type SnapshotScrubber interface {
	ScrubSnapshot(asset.Snapshot) asset.Snapshot
}

// ObservationPersistence writes normalized observations to storage.
// The concrete implementation lives in the platform layer.
type ObservationPersistence interface {
	WriteObservations(path string, snapshots []asset.Snapshot, overwrite, allowSymlink bool) error
}

// ObservationsWriteRequest controls normalized observation output persistence.
type ObservationsWriteRequest struct {
	Path         string
	Snapshots    []asset.Snapshot
	Scrubber     SnapshotScrubber // optional; when set, each snapshot is scrubbed before writing
	Overwrite    bool
	AllowSymlink bool
	Writer       ObservationPersistence // injected from cmd layer
}

// WriteObservationsFile writes observations with fs safety checks and optional
// sanitization.
func WriteObservationsFile(req ObservationsWriteRequest) error {
	if req.Writer == nil {
		return fmt.Errorf("observations writer is required")
	}
	snapshots := req.Snapshots
	if req.Scrubber != nil && len(snapshots) > 0 {
		scrubbed := make([]asset.Snapshot, len(snapshots))
		for i, s := range snapshots {
			scrubbed[i] = req.Scrubber.ScrubSnapshot(s)
		}
		snapshots = scrubbed
	}

	return req.Writer.WriteObservations(req.Path, snapshots, req.Overwrite, req.AllowSymlink)
}
