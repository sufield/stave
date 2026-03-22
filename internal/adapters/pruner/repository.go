package pruner

import (
	"context"
	"fmt"
	"os"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
)

// loadSnapshotCapturedAt opens a snapshot file and returns its CapturedAt timestamp.
func loadSnapshotCapturedAt(ctx context.Context, loader appcontracts.SnapshotReader, path, name string) (time.Time, error) {
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	// #nosec G304 -- path is discovered from directory entries.
	f, err := os.Open(path)
	if err != nil {
		return time.Time{}, fmt.Errorf("open %s: %w", path, err)
	}
	snapshot, loadErr := loader.LoadSnapshotFromReader(ctx, f, name)
	_ = f.Close()
	if loadErr != nil {
		return time.Time{}, fmt.Errorf("failed to load snapshot %s: %w", path, loadErr)
	}
	return snapshot.CapturedAt.UTC(), nil
}

// ListSnapshotFilesFlatWithLoader lists snapshot files directly under observationsDir
// and resolves captured_at via the provided loader.
func ListSnapshotFilesFlatWithLoader(ctx context.Context, observationsDir string, loader appcontracts.SnapshotReader) ([]appcontracts.SnapshotFile, error) {
	if loader == nil {
		return nil, fmt.Errorf("snapshot loader is required")
	}
	return ListSnapshotFilesFlat(observationsDir, ScannerOptions{
		MetadataLoader: func(path, name string) (time.Time, error) {
			return loadSnapshotCapturedAt(ctx, loader, path, name)
		},
	})
}

// ListSnapshotFilesRecursiveWithLoader walks observationsDir recursively and
// resolves captured_at via the provided loader.
func ListSnapshotFilesRecursiveWithLoader(
	ctx context.Context,
	observationsDir string,
	excludeDirs []string,
	loader appcontracts.SnapshotReader,
) ([]appcontracts.SnapshotFile, error) {
	if loader == nil {
		return nil, fmt.Errorf("snapshot loader is required")
	}
	return ListSnapshotFilesRecursive(ctx, observationsDir, ScannerOptions{
		MetadataLoader: func(path, name string) (time.Time, error) {
			return loadSnapshotCapturedAt(ctx, loader, path, name)
		},
		ExcludeDirs: excludeDirs,
	})
}
