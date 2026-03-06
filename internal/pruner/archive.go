package pruner

import (
	"fmt"
	"io"
	"os"

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
func ApplyArchive(in ArchiveInput) (ArchiveResult, error) {
	if err := fsutil.SafeMkdirAll(in.ArchiveDir, fsutil.WriteOptions{
		Perm:         0o700,
		AllowSymlink: in.Options.AllowSymlink,
	}); err != nil {
		return ArchiveResult{}, fmt.Errorf("create archive directory: %w", err)
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

// MoveSnapshotFile attempts a fast rename and falls back to copy+remove.
func MoveSnapshotFile(src, dst string, opts MoveOptions) error {
	// Fast path for same-filesystem moves.
	if err := os.Rename(src, dst); err == nil {
		return nil
	}

	// #nosec G304 -- src comes from previously enumerated snapshot files under observations directories.
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	writeOpts := fsutil.DefaultWriteOpts()
	writeOpts.Overwrite = opts.Overwrite
	writeOpts.AllowSymlink = opts.AllowSymlink
	out, err := fsutil.SafeCreateFile(dst, writeOpts)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	if err := out.Sync(); err != nil {
		return err
	}
	return os.Remove(src)
}
