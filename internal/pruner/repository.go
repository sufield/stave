package pruner

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
)

// SnapshotObservationLoader loads snapshot documents from a reader.
type SnapshotObservationLoader interface {
	LoadSnapshotFromReader(ctx context.Context, r io.Reader, sourceName string) (asset.Snapshot, error)
}

// loadSnapshotCapturedAt opens a snapshot file and returns its CapturedAt timestamp.
func loadSnapshotCapturedAt(loader SnapshotObservationLoader, path, name string) (time.Time, error) {
	// #nosec G304 -- path is discovered from directory entries.
	f, err := os.Open(path)
	if err != nil {
		return time.Time{}, fmt.Errorf("open %s: %w", path, err)
	}
	// TODO: thread context from callers instead of using context.TODO.
	snapshot, loadErr := loader.LoadSnapshotFromReader(context.TODO(), f, name)
	_ = f.Close()
	if loadErr != nil {
		return time.Time{}, fmt.Errorf("failed to load snapshot %s: %w", path, loadErr)
	}
	return snapshot.CapturedAt.UTC(), nil
}

// ListSnapshotFilesFlatWithLoader lists snapshot files directly under observationsDir
// and resolves captured_at via the provided loader.
func ListSnapshotFilesFlatWithLoader(observationsDir string, loader SnapshotObservationLoader) ([]SnapshotFile, error) {
	if loader == nil {
		return nil, fmt.Errorf("snapshot loader is required")
	}
	return ListSnapshotFilesFlat(observationsDir, func(path, name string) (time.Time, error) {
		return loadSnapshotCapturedAt(loader, path, name)
	})
}

// ListSnapshotFilesRecursiveWithLoader walks observationsDir recursively and
// resolves captured_at via the provided loader.
func ListSnapshotFilesRecursiveWithLoader(
	observationsDir string,
	excludeDirs []string,
	loader SnapshotObservationLoader,
) ([]SnapshotFile, error) {
	if loader == nil {
		return nil, fmt.Errorf("snapshot loader is required")
	}
	return ListSnapshotFilesRecursive(observationsDir, excludeDirs, func(path, name string) (time.Time, error) {
		return loadSnapshotCapturedAt(loader, path, name)
	})
}
