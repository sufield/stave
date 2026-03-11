package pruner

import (
	"cmp"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// maxSnapshotFiles is the safety cap on snapshot file enumeration.
// Prevents unbounded memory growth from directories with millions of files.
// 100 000 files ≈ 10–20 MB of SnapshotFile structs in memory.
// This is a var (not const) so tests can temporarily lower it.
var maxSnapshotFiles = 100_000

// ErrTooManySnapshots indicates the observations directory exceeds the
// enumeration safety limit.
var ErrTooManySnapshots = errors.New("too many snapshot files")

// SnapshotFile represents one snapshot file discovered on disk.
type SnapshotFile struct {
	Path       string
	RelPath    string
	Name       string
	CapturedAt time.Time
}

// LoadCapturedAtFunc resolves captured_at for the snapshot file at path.
type LoadCapturedAtFunc func(path, name string) (time.Time, error)

// ListSnapshotFilesFlat lists JSON snapshot files directly under observationsDir.
func ListSnapshotFilesFlat(observationsDir string, loadCapturedAt LoadCapturedAtFunc) ([]SnapshotFile, error) {
	if loadCapturedAt == nil {
		return nil, fmt.Errorf("snapshot metadata loader is required")
	}

	entries, err := os.ReadDir(observationsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read observations directory: %w", err)
	}

	files := make([]SnapshotFile, 0, min(len(entries), maxSnapshotFiles))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		// Skip symlinks — they could point outside the observations directory.
		if entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		if len(files) >= maxSnapshotFiles {
			return nil, snapshotLimitError(observationsDir)
		}
		path := filepath.Join(observationsDir, entry.Name())
		capturedAt, loadErr := loadCapturedAt(path, entry.Name())
		if loadErr != nil {
			return nil, loadErr
		}
		files = append(files, SnapshotFile{
			Path:       path,
			RelPath:    entry.Name(),
			Name:       entry.Name(),
			CapturedAt: capturedAt.UTC(),
		})
	}

	sortByNameFallback(files)
	return files, nil
}

// ListSnapshotFilesRecursive walks observationsDir recursively using WalkDir
// for efficient enumeration (avoids extra Lstat syscalls).
// excludeDirs is a list of absolute paths to skip (e.g., archive dir).
// Directories starting with "_" are skipped.
// RelPath is relative to observationsDir, using forward slashes.
func ListSnapshotFilesRecursive(
	observationsDir string,
	excludeDirs []string,
	loadCapturedAt LoadCapturedAtFunc,
) ([]SnapshotFile, error) {
	if loadCapturedAt == nil {
		return nil, fmt.Errorf("snapshot metadata loader is required")
	}

	absRoot, err := filepath.Abs(observationsDir)
	if err != nil {
		return nil, fmt.Errorf("resolve observations root: %w", err)
	}

	excludeSet, err := buildExcludedDirSet(excludeDirs)
	if err != nil {
		return nil, err
	}

	var files []SnapshotFile
	walkErr := filepath.WalkDir(absRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return filterDir(path, d, absRoot, excludeSet)
		}
		if !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		// Skip symlinks — they could point outside the observations directory.
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if len(files) >= maxSnapshotFiles {
			return snapshotLimitError(observationsDir)
		}
		capturedAt, loadErr := loadCapturedAt(path, d.Name())
		if loadErr != nil {
			return loadErr
		}
		relPath, relErr := relativeSnapshotPath(absRoot, path)
		if relErr != nil {
			return relErr
		}
		files = append(files, SnapshotFile{
			Path:       path,
			RelPath:    relPath,
			Name:       d.Name(),
			CapturedAt: capturedAt.UTC(),
		})
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}

	sortByRelPathFallback(files)
	return files, nil
}

func buildExcludedDirSet(excludeDirs []string) (map[string]bool, error) {
	excludeSet := make(map[string]bool, len(excludeDirs))
	for _, dir := range excludeDirs {
		abs, err := filepath.Abs(dir)
		if err != nil {
			return nil, fmt.Errorf("resolve exclude directory %s: %w", dir, err)
		}
		excludeSet[abs] = true
	}
	return excludeSet, nil
}

func filterDir(path string, d os.DirEntry, absRoot string, excludeSet map[string]bool) error {
	abs, _ := filepath.Abs(path)
	if excludeSet[abs] {
		return filepath.SkipDir
	}
	if path != absRoot && strings.HasPrefix(d.Name(), "_") {
		return filepath.SkipDir
	}
	return nil
}

func relativeSnapshotPath(absRoot, path string) (string, error) {
	relPath, err := filepath.Rel(absRoot, path)
	if err != nil {
		return "", fmt.Errorf("relative path for %s: %w", path, err)
	}
	return filepath.ToSlash(relPath), nil
}

func snapshotLimitError(dir string) error {
	return fmt.Errorf("%w: directory %s contains more than %d JSON files; "+
		"prune older snapshots first to reduce the count",
		ErrTooManySnapshots, dir, maxSnapshotFiles)
}

// sortByNameFallback sorts by CapturedAt, breaking ties by Name.
func sortByNameFallback(files []SnapshotFile) {
	slices.SortFunc(files, func(a, b SnapshotFile) int {
		if c := a.CapturedAt.Compare(b.CapturedAt); c != 0 {
			return c
		}
		return cmp.Compare(a.Name, b.Name)
	})
}

// sortByRelPathFallback sorts by CapturedAt, breaking ties by RelPath.
func sortByRelPathFallback(files []SnapshotFile) {
	slices.SortFunc(files, func(a, b SnapshotFile) int {
		if c := a.CapturedAt.Compare(b.CapturedAt); c != 0 {
			return c
		}
		return cmp.Compare(a.RelPath, b.RelPath)
	})
}
