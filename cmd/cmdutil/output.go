package cmdutil

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sufield/stave/internal/platform/fsutil"
)

// FileOptions configures the behavior of output file creation.
type FileOptions struct {
	Overwrite     bool
	AllowSymlinks bool
	DirPerms      os.FileMode
}

// OpenOutputFile ensures the destination directory exists and opens the file
// for writing. It applies safety checks for symlinks and existing files.
func OpenOutputFile(path string, opts FileOptions) (*os.File, error) {
	parent := filepath.Dir(path)
	if strings.TrimSpace(parent) != "" && parent != "." {
		mkdirOpts := fsutil.WriteOptions{
			Perm:         opts.DirPerms,
			AllowSymlink: opts.AllowSymlinks,
		}
		if err := fsutil.SafeMkdirAll(parent, mkdirOpts); err != nil {
			return nil, fmt.Errorf("creating directory %q: %w", parent, err)
		}
	}

	writeOpts := fsutil.DefaultWriteOpts()
	writeOpts.Overwrite = opts.Overwrite
	writeOpts.AllowSymlink = opts.AllowSymlinks

	f, err := fsutil.SafeCreateFile(path, writeOpts)
	if err != nil {
		return nil, fmt.Errorf("creating file %q: %w", path, err)
	}

	return f, nil
}
