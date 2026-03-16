package fsops

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sufield/stave/internal/platform/fsutil"
)

// DeleteFile represents a filesystem path selected for deletion.
type DeleteFile struct {
	Path string
}

// DeleteInput defines deletion execution dependencies.
type DeleteInput struct {
	// ObservationsDir is the root directory containing snapshot files.
	// All file paths must resolve within this directory.
	ObservationsDir string
	Files           []DeleteFile
	Remove          func(string) error
}

// DeleteResult captures deletion execution totals.
type DeleteResult struct {
	Deleted int
}

// ApplyDelete executes the prune inner loop over selected files.
// It is intentionally CLI-agnostic so command handlers can stay thin.
//
// All file paths are validated to reside within ObservationsDir before
// any removals begin. Symlinks are rejected to prevent removal of files
// outside the intended scope.
//
// NOTE: Fail-fast on error is intentional. For a security tool, stopping
// immediately on a permission or filesystem error is safer than continuing,
// which could mask security-relevant conditions. The caller can inspect
// DeleteResult.Deleted to determine how many files were removed before the
// error.
//
// NOTE: A TOCTOU window exists between file enumeration and deletion. For
// a local CLI tool operating on operator-controlled directories, this is
// an accepted trade-off. Metadata verification before each remove is
// deferred as a future hardening measure.
func ApplyDelete(in DeleteInput) (DeleteResult, error) {
	remove := in.Remove
	if remove == nil {
		remove = os.Remove
	}

	// Validate all file paths are contained within ObservationsDir
	// before executing any removals.
	absObs, err := filepath.Abs(in.ObservationsDir)
	if err != nil {
		return DeleteResult{}, fmt.Errorf("resolve observations directory: %w", err)
	}
	obsPrefix := absObs + string(filepath.Separator)
	for _, file := range in.Files {
		absPath, absErr := filepath.Abs(file.Path)
		if absErr != nil {
			return DeleteResult{}, fmt.Errorf("resolve path %s: %w", file.Path, absErr)
		}
		if absPath != absObs && !strings.HasPrefix(absPath, obsPrefix) {
			return DeleteResult{}, fmt.Errorf("%w: %s escapes observations directory %s",
				fsutil.ErrPathTraversal, file.Path, in.ObservationsDir)
		}
	}

	out := DeleteResult{}
	for _, file := range in.Files {
		// Verify the target is not a symlink before removal.
		fi, lstatErr := os.Lstat(file.Path)
		if lstatErr != nil {
			if os.IsNotExist(lstatErr) {
				continue
			}
			return out, fmt.Errorf("stat %s: %w", file.Path, lstatErr)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return out, fmt.Errorf("refusing to remove symlink %s: "+
				"symlinks in observation directories are not supported", file.Path)
		}
		if err := remove(file.Path); err != nil {
			return out, fmt.Errorf("remove %s: %w", file.Path, err)
		}
		out.Deleted++
	}
	return out, nil
}
