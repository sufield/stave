package plan

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sufield/stave/internal/adapters/pruner/fsops"
	"github.com/sufield/stave/internal/platform/fsutil"
	snapshotdomain "github.com/sufield/stave/pkg/alpha/domain/snapshot"
)

// EntryProcessor handles the filesystem action for a single plan entry.
type EntryProcessor interface {
	Process(entry snapshotdomain.PlanEntry) error
}

// SnapshotPlanApplyInput defines apply inputs for snapshot plan execution.
type SnapshotPlanApplyInput struct {
	Entries          []snapshotdomain.PlanEntry
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
	processor, err := newProcessor(in)
	if err != nil {
		return SnapshotPlanApplyResult{}, err
	}

	result := SnapshotPlanApplyResult{}
	for _, entry := range in.Entries {
		if entry.Action == snapshotdomain.ActionKeep {
			continue
		}
		if err := processor.Process(entry); err != nil {
			return result, fmt.Errorf("entry %s: %w", entry.RelPath, err)
		}
		result.Applied++
		if in.ArchiveDir != "" {
			result.Archived++
		} else {
			result.Deleted++
		}
	}
	return result, nil
}

func newProcessor(in SnapshotPlanApplyInput) (EntryProcessor, error) {
	if in.ArchiveDir != "" {
		return newArchiver(in.ObservationsRoot, in.ArchiveDir, in.AllowSymlink)
	}
	return &deleter{obsRoot: in.ObservationsRoot}, nil
}

// archiver moves snapshot files from observations to an archive directory.
type archiver struct {
	obsRoot      string
	archiveDir   string
	allowSymlink bool
	createdDirs  map[string]struct{}
}

func newArchiver(obsRoot, archiveDir string, allowSymlink bool) (*archiver, error) {
	if err := fsutil.SafeMkdirAll(archiveDir, fsutil.WriteOptions{
		Perm:         0o700,
		AllowSymlink: allowSymlink,
	}); err != nil {
		return nil, fmt.Errorf("create archive directory: %w", err)
	}
	return &archiver{
		obsRoot:      obsRoot,
		archiveDir:   archiveDir,
		allowSymlink: allowSymlink,
		createdDirs:  make(map[string]struct{}),
	}, nil
}

func (a *archiver) Process(entry snapshotdomain.PlanEntry) error {
	src, err := fsutil.JoinWithinRoot(a.obsRoot, entry.RelPath)
	if err != nil {
		return fmt.Errorf("archive %s: source: %w", entry.RelPath, err)
	}
	dst, err := fsutil.JoinWithinRoot(a.archiveDir, entry.RelPath)
	if err != nil {
		return fmt.Errorf("archive %s: destination: %w", entry.RelPath, err)
	}
	if err := a.ensureParentDir(dst, entry.RelPath); err != nil {
		return err
	}
	if err := fsops.MoveSnapshotFile(src, dst, fsops.MoveOptions{AllowSymlink: a.allowSymlink}); err != nil {
		return fmt.Errorf("archive %s: %w", entry.RelPath, err)
	}
	return nil
}

func (a *archiver) ensureParentDir(dst, relPath string) error {
	parentDir := filepath.Dir(dst)
	if _, ok := a.createdDirs[parentDir]; ok {
		return nil
	}
	if err := fsutil.SafeMkdirAll(parentDir, fsutil.WriteOptions{
		Perm:         0o700,
		AllowSymlink: a.allowSymlink,
	}); err != nil {
		return fmt.Errorf("archive create parent for %s: %w", relPath, err)
	}
	a.createdDirs[parentDir] = struct{}{}
	return nil
}

// deleter removes snapshot files from the observations directory.
type deleter struct {
	obsRoot string
}

func (d *deleter) Process(entry snapshotdomain.PlanEntry) error {
	src, err := fsutil.JoinWithinRoot(d.obsRoot, entry.RelPath)
	if err != nil {
		return fmt.Errorf("prune %s: %w", entry.RelPath, err)
	}
	if err := os.Remove(src); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("prune %s: %w", entry.RelPath, err)
	}
	return nil
}
