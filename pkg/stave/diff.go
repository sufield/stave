package stave

import (
	"context"
	"errors"
	"fmt"

	"github.com/sufield/stave/internal/app/snapshotdiff"
	"github.com/sufield/stave/internal/core/asset"
)

// SnapshotDiff is the structured difference between two observation
// snapshots: per-property changes plus added and removed assets,
// filtered to fields the catalog evaluates.
type SnapshotDiff = snapshotdiff.DiffResult

// DiffSnapshots compares the latest snapshot in beforeDir against the
// latest snapshot in afterDir and returns the structured delta. Each
// directory is loaded independently and its newest snapshot (by
// captured_at) is selected — so the two paths may be entirely
// separate point-in-time captures. Deterministic and offline.
func DiffSnapshots(ctx context.Context, beforeDir, afterDir string) (*SnapshotDiff, error) {
	if beforeDir == "" || afterDir == "" {
		return nil, errors.New("stave.DiffSnapshots: beforeDir and afterDir are required")
	}
	before, err := latestSnapshot(ctx, beforeDir)
	if err != nil {
		return nil, fmt.Errorf("load before snapshot: %w", err)
	}
	after, err := latestSnapshot(ctx, afterDir)
	if err != nil {
		return nil, fmt.Errorf("load after snapshot: %w", err)
	}
	return snapshotdiff.Diff(before, after), nil
}

// latestSnapshot loads every snapshot in dir and returns the one with
// the newest captured_at. Errors if the directory holds no snapshots.
func latestSnapshot(ctx context.Context, dir string) (asset.Snapshot, error) {
	snaps, err := loadSnapshots(ctx, dir)
	if err != nil {
		return asset.Snapshot{}, err
	}
	latest := snaps[0]
	for _, s := range snaps[1:] {
		if s.CapturedAt.After(latest.CapturedAt) {
			latest = s
		}
	}
	return latest, nil
}
