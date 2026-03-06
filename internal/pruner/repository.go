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

// ListSnapshotFilesFlatWithLoader lists snapshot files directly under observationsDir
// and resolves captured_at via the provided loader.
func ListSnapshotFilesFlatWithLoader(observationsDir string, loader SnapshotObservationLoader) ([]SnapshotFile, error) {
	if loader == nil {
		return nil, fmt.Errorf("snapshot loader is required")
	}
	return ListSnapshotFilesFlat(observationsDir, func(path, name string) (time.Time, error) {
		// #nosec G304 -- path is discovered from directory entries under observationsDir.
		f, openErr := os.Open(path)
		if openErr != nil {
			return time.Time{}, fmt.Errorf("open %s: %w", path, openErr)
		}
		snapshot, loadErr := loader.LoadSnapshotFromReader(context.Background(), f, name)
		_ = f.Close()
		if loadErr != nil {
			return time.Time{}, fmt.Errorf("failed to load snapshot %s: %w", path, loadErr)
		}
		return snapshot.CapturedAt.UTC(), nil
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
		// #nosec G304 -- path is discovered via recursive walk rooted at observationsDir.
		f, openErr := os.Open(path)
		if openErr != nil {
			return time.Time{}, fmt.Errorf("open %s: %w", path, openErr)
		}
		snapshot, loadErr := loader.LoadSnapshotFromReader(context.Background(), f, name)
		_ = f.Close()
		if loadErr != nil {
			return time.Time{}, fmt.Errorf("failed to load snapshot %s: %w", path, loadErr)
		}
		return snapshot.CapturedAt.UTC(), nil
	})
}
