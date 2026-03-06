package pruner

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

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

	files := make([]SnapshotFile, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
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

	sort.Slice(files, func(i, j int) bool {
		if !files[i].CapturedAt.Equal(files[j].CapturedAt) {
			return files[i].CapturedAt.Before(files[j].CapturedAt)
		}
		return files[i].Name < files[j].Name
	})
	return files, nil
}

// ListSnapshotFilesRecursive walks observationsDir recursively.
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

	excludeSet := buildExcludedDirSet(excludeDirs)
	var files []SnapshotFile
	state := snapshotWalkState{
		absRoot:        absRoot,
		excludeSet:     excludeSet,
		files:          &files,
		loadCapturedAt: loadCapturedAt,
	}
	walkErr := filepath.Walk(absRoot, func(path string, info os.FileInfo, walkErr error) error {
		return walkSnapshotFile(path, info, walkErr, state)
	})
	if walkErr != nil {
		return nil, walkErr
	}

	sort.Slice(files, func(i, j int) bool {
		if !files[i].CapturedAt.Equal(files[j].CapturedAt) {
			return files[i].CapturedAt.Before(files[j].CapturedAt)
		}
		return files[i].RelPath < files[j].RelPath
	})
	return files, nil
}

func buildExcludedDirSet(excludeDirs []string) map[string]bool {
	excludeSet := make(map[string]bool, len(excludeDirs))
	for _, dir := range excludeDirs {
		if abs, err := filepath.Abs(dir); err == nil {
			excludeSet[abs] = true
		}
	}
	return excludeSet
}

type snapshotWalkState struct {
	absRoot        string
	excludeSet     map[string]bool
	files          *[]SnapshotFile
	loadCapturedAt LoadCapturedAtFunc
}

func walkSnapshotFile(path string, info os.FileInfo, walkErr error, state snapshotWalkState) error {
	if walkErr != nil {
		return walkErr
	}
	if info.IsDir() {
		return walkSnapshotDir(path, info, state.absRoot, state.excludeSet)
	}
	if !strings.HasSuffix(info.Name(), ".json") {
		return nil
	}
	capturedAt, err := state.loadCapturedAt(path, info.Name())
	if err != nil {
		return err
	}
	relPath, err := relativeSnapshotPath(state.absRoot, path)
	if err != nil {
		return err
	}
	*state.files = append(*state.files, SnapshotFile{
		Path:       path,
		RelPath:    relPath,
		Name:       info.Name(),
		CapturedAt: capturedAt.UTC(),
	})
	return nil
}

func walkSnapshotDir(path string, info os.FileInfo, absRoot string, excludeSet map[string]bool) error {
	abs, _ := filepath.Abs(path)
	if excludeSet[abs] {
		return filepath.SkipDir
	}
	if path != absRoot && strings.HasPrefix(info.Name(), "_") {
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
