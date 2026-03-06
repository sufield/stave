// Package state manages persistent CLI state markers (e.g. first-run hints).
package state

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/sufield/stave/internal/envvar"
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
	// #nosec G301 -- marker directory is local CLI config state, not an externally served path.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	// #nosec G306 -- marker file is local CLI state, not an externally served path.
	return os.WriteFile(path, []byte("seen\n"), 0o600)
}
