package bisect

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
)

// LoadSnapshotDir reads all JSON snapshot files from a directory, parses
// them, sorts chronologically by CapturedAt, and returns the ordered slice.
// readFile must enforce size limits (e.g., fsutil.ReadFileLimited).
// Files that fail to parse are skipped with a warning.
func LoadSnapshotDir(dir string, readFile func(string) ([]byte, error), logger *slog.Logger) ([]asset.Snapshot, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read snapshot directory %q: %w", dir, err)
	}

	var snapshots []asset.Snapshot
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, err := readFile(path)
		if err != nil {
			logger.Warn("skipping unreadable snapshot", "path", path, "error", err)
			continue
		}

		var snap asset.Snapshot
		if err := json.Unmarshal(data, &snap); err != nil {
			logger.Warn("skipping unparseable snapshot", "path", path, "error", err)
			continue
		}
		if snap.CapturedAt.IsZero() {
			logger.Warn("skipping snapshot without captured_at", "path", path)
			continue
		}
		snapshots = append(snapshots, snap)
	}

	if len(snapshots) == 0 {
		return nil, fmt.Errorf("no valid snapshots found in %q", dir)
	}

	slices.SortFunc(snapshots, func(a, b asset.Snapshot) int {
		return a.CapturedAt.Compare(b.CapturedAt)
	})

	return snapshots, nil
}
