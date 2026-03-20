package plan

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sufield/stave/internal/adapters/pruner/fsops"
	"github.com/sufield/stave/internal/platform/fsutil"
	snapshotdomain "github.com/sufield/stave/pkg/alpha/domain/snapshot"
)

// PlanEntry is a type alias for the domain snapshot PlanEntry.
type PlanEntry = snapshotdomain.PlanEntry

// SnapshotPlanApplyInput defines apply inputs for snapshot plan execution.
type SnapshotPlanApplyInput struct {
	Entries          []PlanEntry
	ObservationsRoot string
	ArchiveDir       string
	AllowSymlink     bool
}

// SnapshotPlanApplyResult captures apply totals.
type SnapshotPlanApplyResult struct {
	Applied  int
	Archived int
	Deleted  int
}

// ApplySnapshotPlan executes snapshot plan actions against the filesystem.
func ApplySnapshotPlan(in SnapshotPlanApplyInput) (SnapshotPlanApplyResult, error) {
	result := SnapshotPlanApplyResult{}
	isArchive := in.ArchiveDir != ""
	if isArchive {
		if err := fsutil.SafeMkdirAll(in.ArchiveDir, fsutil.WriteOptions{
			Perm:         0o700,
			AllowSymlink: in.AllowSymlink,
		}); err != nil {
			return result, fmt.Errorf("create archive directory: %w", err)
		}
	}

	// Cache parent directories already created to avoid redundant syscalls.
	createdDirs := make(map[string]struct{})

	for _, entry := range in.Entries {
		if entry.Action == snapshotdomain.ActionKeep {
			continue
		}
		if isArchive {
			if err := archiveEntry(entry, in.ObservationsRoot, in.ArchiveDir, in.AllowSymlink, createdDirs); err != nil {
				return result, err
			}
			result.Applied++
			result.Archived++
		} else {
			if err := deleteEntry(entry, in.ObservationsRoot); err != nil {
				return result, err
			}
			result.Applied++
			result.Deleted++
		}
	}

	return result, nil
}

// archiveEntry moves a single snapshot file from obsRoot into archiveDir.
// createdDirs caches parent directories already created during this run.
func archiveEntry(entry PlanEntry, obsRoot, archiveDir string, allowSymlink bool, createdDirs map[string]struct{}) error {
	src, err := fsutil.JoinWithinRoot(obsRoot, entry.RelPath)
	if err != nil {
		return fmt.Errorf("archive %s: source: %w", entry.RelPath, err)
	}
	dst, err := fsutil.JoinWithinRoot(archiveDir, entry.RelPath)
	if err != nil {
		return fmt.Errorf("archive %s: destination: %w", entry.RelPath, err)
	}
	parentDir := filepath.Dir(dst)
	if _, ok := createdDirs[parentDir]; !ok {
		if err := fsutil.SafeMkdirAll(parentDir, fsutil.WriteOptions{
			Perm:         0o700,
			AllowSymlink: allowSymlink,
		}); err != nil {
			return fmt.Errorf("archive create parent for %s: %w", entry.RelPath, err)
		}
		createdDirs[parentDir] = struct{}{}
	}
	if err := fsops.MoveSnapshotFile(src, dst, fsops.MoveOptions{AllowSymlink: allowSymlink}); err != nil {
		return fmt.Errorf("archive %s: %w", entry.RelPath, err)
	}
	return nil
}

// deleteEntry removes a single snapshot file from obsRoot.
func deleteEntry(entry PlanEntry, obsRoot string) error {
	src, err := fsutil.JoinWithinRoot(obsRoot, entry.RelPath)
	if err != nil {
		return fmt.Errorf("prune %s: %w", entry.RelPath, err)
	}
	if err := os.Remove(src); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("prune %s: %w", entry.RelPath, err)
	}
	return nil
}
