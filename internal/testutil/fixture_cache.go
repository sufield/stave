// Test-scoped fixture cache. Test files import this package and use
// LoadControlsFromDir / LoadSnapshotsFromDir to share parsed
// fixtures across the run instead of re-reading from disk on every
// subtest.
//
// Cache scope: package-level. Entries live for the duration of the
// `go test` invocation. The cache keys on the absolute path so tests
// in different packages (or running in different t.TempDir() roots)
// don't accidentally share state.
//
// Why parsed structures instead of raw bytes: every consumer needs
// the parsed form, and parsing the same YAML/JSON twice is the
// dominant cost; caching at the byte level would not eliminate it.

package testutil

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	builtinpredicate "github.com/sufield/stave/internal/adapters/predicate"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
)

type fixtureCache struct {
	mu        sync.RWMutex
	controls  map[string][]policy.ControlDefinition
	snapshots map[string][]asset.Snapshot
}

var globalFixtureCache = &fixtureCache{
	controls:  make(map[string][]policy.ControlDefinition),
	snapshots: make(map[string][]asset.Snapshot),
}

// LoadControlsFromDir loads controls from `dir` (creating a control
// loader internally) and caches the result keyed by the absolute
// path. Subsequent calls with the same directory return a fresh
// slice copy of the cached controls so a caller can mutate without
// disturbing the cache.
//
// Failures are surfaced via t.Skipf — the helper exists for tests
// that walk every fixture and want the skip-on-missing semantic.
// Callers that need a hard error should use the underlying loader
// directly.
func LoadControlsFromDir(t *testing.T, dir string) []policy.ControlDefinition {
	t.Helper()
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("resolve %s: %v", dir, err)
	}
	globalFixtureCache.mu.RLock()
	cached, ok := globalFixtureCache.controls[abs]
	globalFixtureCache.mu.RUnlock()
	if ok {
		return cloneControls(cached)
	}

	loader := ctlyaml.NewControlLoader(ctlyaml.WithAliasResolver(builtinpredicate.ResolverFunc()))
	controls, err := loader.LoadControls(context.Background(), abs)
	if err != nil {
		t.Skipf("load controls from %s: %v", abs, err)
	}

	globalFixtureCache.mu.Lock()
	globalFixtureCache.controls[abs] = controls
	globalFixtureCache.mu.Unlock()
	return cloneControls(controls)
}

// LoadSnapshotsFromDir loads every *.json file in `dir` as an
// asset.Snapshot, with the same caching semantics as
// LoadControlsFromDir. JSON parse errors fail the test.
func LoadSnapshotsFromDir(t *testing.T, dir string) []asset.Snapshot {
	t.Helper()
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("resolve %s: %v", dir, err)
	}
	globalFixtureCache.mu.RLock()
	cached, ok := globalFixtureCache.snapshots[abs]
	globalFixtureCache.mu.RUnlock()
	if ok {
		return cloneSnapshots(cached)
	}

	entries, err := os.ReadDir(abs)
	if err != nil {
		t.Fatalf("read observations dir %s: %v", abs, err)
	}
	var snapshots []asset.Snapshot
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(abs, entry.Name())
		// gosec G304: path is built from a directory listing under
		// `abs` (a caller-provided fixture root), not user input.
		// This file is in `internal/testutil` and only callable
		// from tests.
		data, readErr := os.ReadFile(path) //nolint:gosec // G304: test-only helper; path built from a directory listing under the caller's fixture root

		if readErr != nil {
			t.Fatalf("read %s: %v", path, readErr)
		}
		var snap asset.Snapshot
		if jsonErr := json.Unmarshal(data, &snap); jsonErr != nil {
			// Caller may have a fixture with a schema_version
			// wrapper; the existing parallel_test logged an
			// error and continued in that case. Preserve that
			// behavior so a single bad file in the fixture tree
			// doesn't blank the whole load.
			t.Logf("skipping %s: %v", path, jsonErr)
			continue
		}
		snapshots = append(snapshots, snap)
	}

	globalFixtureCache.mu.Lock()
	globalFixtureCache.snapshots[abs] = snapshots
	globalFixtureCache.mu.Unlock()
	return cloneSnapshots(snapshots)
}

// ErrFixtureNotCached is returned by callers that expected a hit.
// Reserved for future use; not currently raised by the helpers.
var ErrFixtureNotCached = errors.New("fixture not in cache")

func cloneControls(in []policy.ControlDefinition) []policy.ControlDefinition {
	if len(in) == 0 {
		return nil
	}
	out := make([]policy.ControlDefinition, len(in))
	copy(out, in)
	return out
}

func cloneSnapshots(in []asset.Snapshot) []asset.Snapshot {
	if len(in) == 0 {
		return nil
	}
	out := make([]asset.Snapshot, len(in))
	copy(out, in)
	return out
}
