package pruner

import (
	"context"
	"fmt"
	"os"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
)

// loadSnapshotMetadata opens a snapshot file and returns its
// CapturedAt timestamp plus the first asset's ID and type. The
// asset fields are populated as best-effort; a snapshot with no
// assets (rare but possible for placeholder fixtures) returns empty
// strings rather than failing the scan.
func loadSnapshotMetadata(ctx context.Context, loader appcontracts.SnapshotReader, path, name string) (meta SnapshotFileMetadata, err error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return SnapshotFileMetadata{}, ctxErr
	}
	// #nosec G304 -- path is discovered from directory entries.
	f, openErr := os.Open(path)
	if openErr != nil {
		return SnapshotFileMetadata{}, fmt.Errorf("open %s: %w", path, openErr)
	}
	defer func() {
		// Surface late-flush failures from networked filesystems instead
		// of silently dropping them; load errors still take priority.
		if closeErr := f.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close %s: %w", path, closeErr)
		}
	}()
	snapshot, loadErr := loader.LoadSnapshotFromReader(ctx, f, name)
	if loadErr != nil {
		return SnapshotFileMetadata{}, fmt.Errorf("failed to load snapshot %s: %w", path, loadErr)
	}
	out := SnapshotFileMetadata{CapturedAt: snapshot.CapturedAt.UTC()}
	if len(snapshot.Assets) > 0 {
		first := snapshot.Assets[0]
		out.AssetID = first.ID.String()
		out.AssetType = string(first.Type)
	}
	return out, nil
}

// ListSnapshotFilesFlatWithLoader lists snapshot files directly under observationsDir
// and resolves captured_at via the provided loader.
func ListSnapshotFilesFlatWithLoader(ctx context.Context, observationsDir string, loader appcontracts.SnapshotReader) ([]appcontracts.SnapshotFile, error) {
	if loader == nil {
		// No loader: fall through to ListSnapshotFilesFlat which uses
		// file modification time as the default metadata source.
		return ListSnapshotFilesFlat(ctx, observationsDir, ScannerOptions{})
	}
	return ListSnapshotFilesFlat(ctx, observationsDir, ScannerOptions{
		SnapshotMetadataLoader: func(path, name string) (SnapshotFileMetadata, error) {
			return loadSnapshotMetadata(ctx, loader, path, name)
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
		return nil, errSnapshotLoaderRequired
	}
	return ListSnapshotFilesRecursive(ctx, observationsDir, ScannerOptions{
		SnapshotMetadataLoader: func(path, name string) (SnapshotFileMetadata, error) {
			return loadSnapshotMetadata(ctx, loader, path, name)
		},
		ExcludeDirs: excludeDirs,
	})
}
