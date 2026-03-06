package pruner

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sufield/stave/internal/platform/fsutil"
)

// PlanEntry is a single snapshot plan row.
type PlanEntry struct {
	RelPath string
	Action  string
}

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

	for _, entry := range in.Entries {
		if entry.Action == "KEEP" {
			continue
		}
		if isArchive {
			if err := archiveEntry(entry, in.ObservationsRoot, in.ArchiveDir, in.AllowSymlink); err != nil {
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
func archiveEntry(entry PlanEntry, obsRoot, archiveDir string, allowSymlink bool) error {
	src := filepath.Join(obsRoot, entry.RelPath)
	dst := filepath.Join(archiveDir, entry.RelPath)
	if err := fsutil.SafeMkdirAll(filepath.Dir(dst), fsutil.WriteOptions{
		Perm:         0o700,
		AllowSymlink: allowSymlink,
	}); err != nil {
		return fmt.Errorf("archive create parent for %s: %w", entry.RelPath, err)
	}
	if err := os.Rename(src, dst); err != nil {
		return fmt.Errorf("archive %s: %w", entry.RelPath, err)
	}
	return nil
}

// deleteEntry removes a single snapshot file from obsRoot.
func deleteEntry(entry PlanEntry, obsRoot string) error {
	src := filepath.Join(obsRoot, entry.RelPath)
	if err := os.Remove(src); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("prune %s: %w", entry.RelPath, err)
	}
	return nil
}
