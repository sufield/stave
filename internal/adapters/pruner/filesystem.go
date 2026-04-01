package pruner

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
)

// ErrTooManySnapshots indicates the observations directory exceeds the
// enumeration safety limit.
var ErrTooManySnapshots = errors.New("too many snapshot files")

// ScannerOptions configures snapshot file discovery.
type ScannerOptions struct {
	// MetadataLoader resolves captured_at for each discovered file.
	MetadataLoader func(path, name string) (time.Time, error)

	// ExcludeDirs are absolute paths that the recursive scanner should skip.
	ExcludeDirs []string

	// MaxFiles limits the number of files scanned to prevent memory exhaustion.
	// Zero uses the default (100,000).
	MaxFiles int
}

// DefaultMaxFiles is the conservative default safety cap on snapshot
// file enumeration. Override via SetDefaultMaxFiles for environments
// with large snapshot directories.
const DefaultMaxFiles = 100_000

var defaultMaxFiles = DefaultMaxFiles

// SetDefaultMaxFiles overrides the default file scan cap used when
// ScannerOptions.MaxFiles is zero. Values <= 0 are ignored.
func SetDefaultMaxFiles(n int) {
	if n > 0 {
		defaultMaxFiles = n
	}
}

func (o ScannerOptions) maxFiles() int {
	if o.MaxFiles > 0 {
		return o.MaxFiles
	}
	return defaultMaxFiles
}

// ListSnapshotFilesFlat lists JSON snapshot files directly under observationsDir.
func ListSnapshotFilesFlat(ctx context.Context, observationsDir string, opts ScannerOptions) ([]appcontracts.SnapshotFile, error) {
	if opts.MetadataLoader == nil {
		return nil, fmt.Errorf("snapshot metadata loader is required")
	}

	entries, err := os.ReadDir(observationsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read observations directory: %w", err)
	}

	limit := opts.maxFiles()

	// Filter eligible entries first.
	type candidate struct {
		path string
		name string
	}
	var candidates []candidate
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		if len(candidates) >= limit {
			return nil, snapshotLimitError(observationsDir, limit)
		}
		candidates = append(candidates, candidate{
			path: filepath.Join(observationsDir, entry.Name()),
			name: entry.Name(),
		})
	}

	// Load metadata concurrently.
	var (
		mu    sync.Mutex
		files = make([]appcontracts.SnapshotFile, 0, len(candidates))
	)
	g, gctx := errgroup.WithContext(ctx)
	for _, c := range candidates {
		g.Go(func() error {
			if gctxErr := gctx.Err(); gctxErr != nil {
				return gctxErr
			}
			capturedAt, loadErr := opts.MetadataLoader(c.path, c.name)
			if loadErr != nil {
				return fmt.Errorf("load metadata for %s: %w", c.name, loadErr)
			}
			mu.Lock()
			files = append(files, appcontracts.SnapshotFile{
				Path:       c.path,
				RelPath:    c.name,
				Name:       c.name,
				CapturedAt: capturedAt.UTC(),
			})
			mu.Unlock()
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	slices.SortFunc(files, func(a, b appcontracts.SnapshotFile) int {
		if c := a.CapturedAt.Compare(b.CapturedAt); c != 0 {
			return c
		}
		return cmp.Compare(a.Name, b.Name)
	})
	return files, nil
}

// ListSnapshotFilesRecursive walks observationsDir recursively using WalkDir.
// Directories starting with "_" are skipped. Symlinks are skipped.
// RelPath uses forward slashes and is relative to observationsDir.
func ListSnapshotFilesRecursive(ctx context.Context, observationsDir string, opts ScannerOptions) ([]appcontracts.SnapshotFile, error) {
	if opts.MetadataLoader == nil {
		return nil, fmt.Errorf("snapshot metadata loader is required")
	}

	absRoot, err := filepath.Abs(observationsDir)
	if err != nil {
		return nil, fmt.Errorf("resolve observations root: %w", err)
	}

	excludes := make(map[string]bool, len(opts.ExcludeDirs))
	for _, dir := range opts.ExcludeDirs {
		if abs, absErr := filepath.Abs(dir); absErr == nil {
			excludes[abs] = true
		}
	}

	limit := opts.maxFiles()
	var files []appcontracts.SnapshotFile

	walkErr := filepath.WalkDir(absRoot, func(path string, d os.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			return err
		}

		if d.IsDir() {
			return skipDir(path, absRoot, d, excludes)
		}

		if !isSnapshotFile(d) {
			return nil
		}
		if len(files) >= limit {
			return snapshotLimitError(observationsDir, limit)
		}

		capturedAt, loadErr := opts.MetadataLoader(path, d.Name())
		if loadErr != nil {
			return loadErr
		}

		relPath, relErr := filepath.Rel(absRoot, path)
		if relErr != nil {
			return fmt.Errorf("relative path for %s: %w", path, relErr)
		}

		files = append(files, appcontracts.SnapshotFile{
			Path:       path,
			RelPath:    filepath.ToSlash(relPath),
			Name:       d.Name(),
			CapturedAt: capturedAt.UTC(),
		})
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}

	slices.SortFunc(files, func(a, b appcontracts.SnapshotFile) int {
		if c := a.CapturedAt.Compare(b.CapturedAt); c != 0 {
			return c
		}
		return cmp.Compare(a.RelPath, b.RelPath)
	})
	return files, nil
}

func snapshotLimitError(dir string, limit int) error {
	return fmt.Errorf("%w: directory %s contains more than %d JSON files; "+
		"prune older snapshots first to reduce the count",
		ErrTooManySnapshots, dir, limit)
}

// skipDir decides whether to skip a directory during recursive walk.
func skipDir(path, root string, d os.DirEntry, excludes map[string]bool) error {
	abs, _ := filepath.Abs(path)
	if excludes[abs] {
		return filepath.SkipDir
	}
	if path != root && strings.HasPrefix(d.Name(), "_") {
		return filepath.SkipDir
	}
	return nil
}

// isSnapshotFile returns true if the entry is a non-symlink JSON file.
func isSnapshotFile(d os.DirEntry) bool {
	return strings.HasSuffix(d.Name(), ".json") && d.Type()&os.ModeSymlink == 0
}
