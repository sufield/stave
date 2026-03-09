// Package state manages persistent CLI state markers (e.g. first-run hints).
package state

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/sufield/stave/internal/envvar"
	"github.com/sufield/stave/internal/platform/fsutil"
)

const firstRunHintMarkerRel = "stave/.first_run_seen"

// FirstRunMarkerPath returns the path to the first-run seen marker file.
// The path is overridable via STAVE_FIRST_RUN_HINT_FILE for testing.
func FirstRunMarkerPath() (string, error) {
	if override := strings.TrimSpace(os.Getenv(envvar.FirstRunHintFile.Name)); override != "" {
		return filepath.Clean(override), nil
	}
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cfgDir, firstRunHintMarkerRel), nil
}

// MarkFirstRunSeen writes the first-run marker file. It is a no-op if the
// marker already exists, avoiding redundant disk I/O on every command run.
func MarkFirstRunSeen(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	if err := fsutil.SafeMkdirAll(filepath.Dir(path), fsutil.WriteOptions{Perm: 0o700}); err != nil {
		return err
	}
	return fsutil.SafeWriteFile(path, []byte("seen\n"), fsutil.WriteOptions{Perm: 0o600})
}
