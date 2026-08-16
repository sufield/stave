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
	"cmp"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/platform/fsutil"
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
	slices.SortFunc(out, func(a, b policy.ControlDefinition) int {
		return cmp.Compare(a.ID, b.ID)
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
	s := string(id)
	// Skip the first segment (e.g. "ctl")
	_, after, ok := strings.Cut(s, ".")
	if !ok {
		return "unknown"
	}
	// The second segment is between the first dot and the second dot
	before, _, _ := strings.Cut(after, ".")
	if before == "" {
		return "unknown"
	}
	var svc string
	needsLower := false
	for i := 0; i < len(before); i++ {
		if before[i] >= 'A' && before[i] <= 'Z' {
			needsLower = true
			break
		}
	}
	if needsLower {
		svc = strings.ToLower(before)
	} else {
		svc = before
	}
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
	var files []string
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(path, ".json") {
			files = append(files, path)
		}
		return nil
	})
	if len(files) == 0 {
		return &SnapshotStatus{Missing: append([]string{}, services...)}
	}

	have := make(map[string]struct{})
	for _, f := range files {
		data, readErr := fsutil.ReadFileLimited(filepath.Clean(f))
		if readErr != nil {
			continue
		}

		var snap struct {
			Assets []struct {
				Type string `json:"type"`
			} `json:"assets"`
			Snapshots []struct {
				Assets []struct {
					Type string `json:"type"`
				} `json:"assets"`
			} `json:"snapshots"`
		}

		if err := json.Unmarshal(data, &snap); err != nil {
			continue
		}

		for _, a := range snap.Assets {
			for _, svc := range services {
				if _, ok := have[svc]; ok {
					continue
				}
				for _, prefix := range []string{"aws_", "gcp_", "azure_"} {
					target := prefix + svc
					if a.Type == target || strings.HasPrefix(a.Type, target+"_") || strings.HasPrefix(a.Type, target+".") {
						have[svc] = struct{}{}
						break
					}
				}
			}
		}

		for _, s := range snap.Snapshots {
			for _, a := range s.Assets {
				for _, svc := range services {
					if _, ok := have[svc]; ok {
						continue
					}
					for _, prefix := range []string{"aws_", "gcp_", "azure_"} {
						target := prefix + svc
						if a.Type == target || strings.HasPrefix(a.Type, target+"_") || strings.HasPrefix(a.Type, target+".") {
							have[svc] = struct{}{}
							break
						}
					}
				}
			}
		}
	}

	out := &SnapshotStatus{}
	for _, svc := range services {
		if _, ok := have[svc]; ok {
			out.Found = append(out.Found, svc)
		} else {
			out.Missing = append(out.Missing, svc)
		}
	}
	return out
}
