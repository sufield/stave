package cmdutil

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/platform/fsutil"
)

// CreateOutputFile creates parent directories and opens a file for writing,
// respecting --force and --allow-symlink-output flags.
func CreateOutputFile(cmd *cobra.Command, path string) (*os.File, error) {
	parent := filepath.Dir(path)
	if strings.TrimSpace(parent) != "" && parent != "." {
		if err := fsutil.SafeMkdirAll(parent, fsutil.WriteOptions{
			Perm:         0o700,
			AllowSymlink: AllowSymlinkOutEnabled(cmd),
		}); err != nil {
			return nil, fmt.Errorf("create output directory: %w", err)
		}
	}
	opts := fsutil.DefaultWriteOpts()
	opts.Overwrite = ForceEnabled(cmd)
	opts.AllowSymlink = AllowSymlinkOutEnabled(cmd)
	f, err := fsutil.SafeCreateFile(path, opts)
	if err != nil {
		return nil, fmt.Errorf("create output file: %w", err)
	}
	return f, nil
}
