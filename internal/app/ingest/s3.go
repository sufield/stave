package ingest

import (
	"context"
	"fmt"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/platform/observations"
	"github.com/sufield/stave/internal/sanitize"
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

// ObservationsWriteRequest controls normalized observation output persistence.
type ObservationsWriteRequest struct {
	Path         string
	Snapshots    []asset.Snapshot
	Scrub        bool
	Overwrite    bool
	AllowSymlink bool
}

// WriteObservationsFile writes observations with fs safety checks and optional
// sanitization.
func WriteObservationsFile(req ObservationsWriteRequest) error {
	snapshots := req.Snapshots
	if req.Scrub && len(snapshots) > 0 {
		r := sanitize.New()
		scrubbed := make([]asset.Snapshot, len(snapshots))
		for i, s := range snapshots {
			scrubbed[i] = r.ScrubSnapshot(s)
		}
		snapshots = scrubbed
	}

	return observations.WriteJSON(observations.WriteRequest{
		Path:          req.Path,
		SchemaVersion: kernel.SchemaObservation,
		Snapshots:     snapshots,
		Overwrite:     req.Overwrite,
		AllowSymlink:  req.AllowSymlink,
	})
}
