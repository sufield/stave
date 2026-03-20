package fsops

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/sufield/stave/internal/platform/fsutil"
)

// MoveOptions controls safe write behavior for archive file moves.
type MoveOptions struct {
	Overwrite    bool
	AllowSymlink bool
}

// ArchiveMove is a single source->destination move operation.
type ArchiveMove struct {
	Src string
	Dst string
}

// ArchiveInput defines archive execution inputs.
type ArchiveInput struct {
	ArchiveDir string
	Moves      []ArchiveMove
	Options    MoveOptions
}

// ArchiveResult captures archive execution totals.
type ArchiveResult struct {
	Archived int
}

// ApplyArchive executes snapshot archive moves.
// All destination paths must resolve within ArchiveDir.
func ApplyArchive(in ArchiveInput) (ArchiveResult, error) {
	if err := fsutil.SafeMkdirAll(in.ArchiveDir, fsutil.WriteOptions{
		Perm:         0o700,
		AllowSymlink: in.Options.AllowSymlink,
	}); err != nil {
		return ArchiveResult{}, fmt.Errorf("create archive directory: %w", err)
	}

	// Validate all destination paths are contained within ArchiveDir
	// before executing any moves.
	absArchive, err := filepath.Abs(in.ArchiveDir)
	if err != nil {
		return ArchiveResult{}, fmt.Errorf("resolve archive directory: %w", err)
	}
	archivePrefix := absArchive + string(filepath.Separator)
	for _, move := range in.Moves {
		absDst, absErr := filepath.Abs(move.Dst)
		if absErr != nil {
			return ArchiveResult{}, fmt.Errorf("resolve destination %s: %w", move.Dst, absErr)
		}
		if absDst != absArchive && !strings.HasPrefix(absDst, archivePrefix) {
			return ArchiveResult{}, fmt.Errorf("%w: destination %s escapes archive directory %s",
				fsutil.ErrPathTraversal, move.Dst, in.ArchiveDir)
		}
	}

	result := ArchiveResult{}
	for _, move := range in.Moves {
		if err := MoveSnapshotFile(move.Src, move.Dst, in.Options); err != nil {
			return result, fmt.Errorf("archive %s -> %s: %w", move.Src, move.Dst, err)
		}
		result.Archived++
	}
	return result, nil
}

// MoveSnapshotFile moves a file from src to dst with safety guarantees:
//   - Source symlink safety enforced when AllowSymlink is false
//   - Overwrite policy enforced atomically on all code paths
//   - Copy fallback uses atomic temp+rename to prevent partial files
//   - Source file permissions are preserved in the copy fallback
func MoveSnapshotFile(src, dst string, opts MoveOptions) error {
	// Enforce source symlink safety before any operation.
	if !opts.AllowSymlink {
		if err := fsutil.CheckSymlinkSafety(src); err != nil {
			return fmt.Errorf("source: %w", err)
		}
	}

	// Fast path: same-filesystem atomic move.
	if moved, err := tryAtomicMove(src, dst, opts); moved || err != nil {
		return err
	}

	// Slow path: cross-device copy with atomic placement.
	return crossDeviceMove(src, dst, opts)
}

// tryAtomicMove attempts a same-filesystem move with correct overwrite semantics.
// Returns (true, nil) on success, (false, nil) on cross-device fallthrough,
// and (false, err) on policy violations.
func tryAtomicMove(src, dst string, opts MoveOptions) (bool, error) {
	// Check destination symlink safety before any filesystem mutation.
	if !opts.AllowSymlink {
		if err := fsutil.CheckSymlinkSafety(dst); err != nil {
			return false, err
		}
	}

	if opts.Overwrite {
		// os.Rename atomically replaces dst; safe when overwrite is permitted.
		if err := os.Rename(src, dst); err == nil {
			return true, nil
		}
		// Cross-device — fall through to copy path.
		return false, nil
	}

	// !opts.Overwrite: os.Link fails atomically if dst exists (EEXIST),
	// enforcing the no-overwrite policy without a TOCTOU window.
	if err := os.Link(src, dst); err == nil {
		if removeErr := os.Remove(src); removeErr != nil {
			// Link succeeded but source removal failed — roll back.
			_ = os.Remove(dst)
			return false, fmt.Errorf("remove source after link: %w", removeErr)
		}
		return true, nil
	}

	// Distinguish "dst exists" (policy violation) from "cross-device" (fallthrough).
	if _, statErr := os.Lstat(dst); statErr == nil {
		return false, fmt.Errorf("%w: %s (use --force to overwrite)", fsutil.ErrFileExists, dst)
	}
	// Cross-device or other link error — fall through to copy path.
	return false, nil
}

// crossDeviceMove copies src to dst via a temp file and atomic rename,
// preventing partial files on error and preserving source permissions.
func crossDeviceMove(src, dst string, opts MoveOptions) error {
	// Lstat source to detect symlinks before opening.
	srcInfo, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if !opts.AllowSymlink && srcInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("source: %w: %s", fsutil.ErrSymlinkForbidden, src)
	}

	// #nosec G304 -- src comes from previously enumerated snapshot files.
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	// Verify the opened handle matches Lstat to close the source TOCTOU window.
	if !opts.AllowSymlink {
		handleInfo, statErr := in.Stat()
		if statErr != nil {
			return fmt.Errorf("source security check failed: %w", statErr)
		}
		if !os.SameFile(handleInfo, srcInfo) {
			return fmt.Errorf("source: %w: %s (changed between check and open)",
				fsutil.ErrSymlinkForbidden, src)
		}
	}

	// Write to a temp file in the destination directory so the final
	// rename is same-filesystem and atomic.
	dstDir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dstDir, ".stave-mv-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	// On any error, clean up the temp file.
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	// Preserve source file permissions.
	if err := tmp.Chmod(srcInfo.Mode().Perm()); err != nil {
		return fmt.Errorf("set permissions: %w", err)
	}

	if _, err := io.Copy(tmp, in); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	// Enforce destination policies and atomically place the file.
	if !opts.AllowSymlink {
		if err := fsutil.CheckSymlinkSafety(dst); err != nil {
			return err
		}
	}

	if !opts.Overwrite {
		// os.Link fails atomically if dst exists, enforcing no-overwrite.
		if err := os.Link(tmpPath, dst); err != nil {
			if _, statErr := os.Lstat(dst); statErr == nil {
				return fmt.Errorf("%w: %s (use --force to overwrite)", fsutil.ErrFileExists, dst)
			}
			return fmt.Errorf("finalize move: %w", err)
		}
		_ = os.Remove(tmpPath)
	} else {
		if err := os.Rename(tmpPath, dst); err != nil {
			return fmt.Errorf("finalize move: %w", err)
		}
	}

	committed = true
	return os.Remove(src)
}
