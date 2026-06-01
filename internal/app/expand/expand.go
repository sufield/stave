// Package expand provides the pure helpers that drive cmd/expand:
// archetype-based control filtering, service-tag derivation from
// control IDs, and snapshot scanning to confirm an archetype's
// service set is observable.
//
// cmd/expand stays as the CLI entry point and renderer; this
// package holds the data transformations so they can be unit-tested
// without going through Cobra and so future library callers
// (programmatic archetype expansion, packs UI) can reuse the logic.
package expand

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// FilterByArchetype returns controls whose Archetype matches id,
// sorted by control ID for deterministic output. Equality on
// Archetype is case-sensitive — archetype IDs are lowercase by
// convention but the comparison is exact, not normalized.
func FilterByArchetype(controls []policy.ControlDefinition, id string) []policy.ControlDefinition {
	target := kernel.ArchetypeID(id)
	out := make([]policy.ControlDefinition, 0)
	for i := range controls {
		if controls[i].Archetype == target {
			out = append(out, controls[i])
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ID == out[j].ID {
			return false
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// ServiceFromControlID derives a lowercase service tag from the
// control ID's second segment. CTL.SECRETS.* and CTL.SECRETSMANAGER.*
// both collapse to "secretsmanager" so expand grouping matches the
// archetype catalog's service vocabulary.
//
// Returns "unknown" for malformed IDs (fewer than two dot-separated
// segments) so callers can handle that as a single bucket rather
// than being forced into nil-checks.
func ServiceFromControlID(id kernel.ControlID) string {
	parts := strings.Split(string(id), ".")
	if len(parts) < 2 {
		return "unknown"
	}
	svc := strings.ToLower(parts[1])
	if svc == "secrets" {
		return "secretsmanager"
	}
	return svc
}

// SnapshotStatus reports which of the archetype's services have at
// least one matching observation file in the snapshots directory.
type SnapshotStatus struct {
	Found   []string `json:"found"`
	Missing []string `json:"missing"`
}

// ScanSnapshots walks the observations directory looking for
// asset_type strings that match each service. Returns nil when dir
// is empty (the snapshot section is then omitted from output).
//
// Errors during walk degrade to "all services missing" rather than
// failing the whole expand — this is decorative coverage data, not
// foundational for the user's primary archetype lookup.
func ScanSnapshots(dir string, services []string) *SnapshotStatus {
	if dir == "" {
		return nil
	}
	dir = filepath.Clean(dir)
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(files) == 0 {
		return &SnapshotStatus{Missing: append([]string{}, services...)}
	}

	have := make(map[string]bool)
	for _, f := range files {
		data, readErr := os.ReadFile(filepath.Clean(f)) //nolint:gosec // CLI tool reads user-provided observation paths.
		if readErr != nil {
			continue
		}
		text := string(data)
		for _, svc := range services {
			if have[svc] {
				continue
			}
			needle := "aws_" + svc
			if strings.Contains(text, needle) {
				have[svc] = true
			}
		}
	}

	out := &SnapshotStatus{}
	for _, svc := range services {
		if have[svc] {
			out.Found = append(out.Found, svc)
		} else {
			out.Missing = append(out.Missing, svc)
		}
	}
	return out
}
