package manifest

import (
	"os"
	"path/filepath"

	"github.com/sufield/stave/internal/platform/fsutil"
)

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := fsutil.CheckSymlinkSafety(path); err != nil {
		return err
	}

	dir := filepath.Dir(path)
	base := filepath.Base(path)

	tmpFile, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	cleanup := func() {
		_ = os.Remove(tmpPath)
	}
	defer cleanup()

	if err := tmpFile.Chmod(perm); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	// #nosec G703 -- destination path is a local CLI output path; symlink safety checked above.
	return os.Rename(tmpPath, path)
}
