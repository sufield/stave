package cel

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// TestCELParallelEvaluation runs the CEL evaluator against all e2e fixtures
// and reports compile/eval failures. This validates that the CEL compiler
// produces results for all built-in controls.
func TestCELParallelEvaluation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: walks all e2e fixtures for parallel CEL evaluation")
	}
	compiler, err := NewCompiler()
	if err != nil {
		t.Fatal(err)
	}

	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
	fixtureRoot := filepath.Join(repoRoot, "testdata", "e2e")

	if _, statErr := os.Stat(fixtureRoot); statErr != nil {
		t.Skipf("e2e fixtures not found at %s", fixtureRoot)
	}

	entries, err := os.ReadDir(fixtureRoot)
	if err != nil {
		t.Fatal(err)
	}

	totalChecks := 0
	celOK := 0

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		controlDir := filepath.Join(fixtureRoot, name, "controls")
		obsDir := filepath.Join(fixtureRoot, name, "observations")

		if _, err := os.Stat(controlDir); err != nil {
			continue
		}
		if _, err := os.Stat(obsDir); err != nil {
			continue
		}

		t.Run(name, func(t *testing.T) {
			controls := loadControlsFromDir(t, controlDir)
			snapshots := loadSnapshotsFromDir(t, obsDir)

			for _, snap := range snapshots {
				for _, a := range snap.Assets {
					for _, ctl := range controls {
						if len(ctl.UnsafePredicate.Any) == 0 && len(ctl.UnsafePredicate.All) == 0 {
							continue
						}
						totalChecks++

						cp, compileErr := compiler.Compile(ctl.UnsafePredicate)
						if compileErr != nil {
							t.Errorf("compile failed for control %s: %v", ctl.ID, compileErr)
							continue
						}

						_, evalErr := Evaluate(cp, a, snap.Identities, ctl.Params.Raw())
						if evalErr != nil {
							t.Errorf("eval failed for control %s on asset %s: %v", ctl.ID, a.ID, evalErr)
							continue
						}

						celOK++
					}
				}
			}
		})
	}

	t.Logf("CEL parallel run: %d checks, %d successful", totalChecks, celOK)
	if totalChecks == 0 {
		t.Fatal("expected at least one parallel check")
	}
}

func loadControlsFromDir(t *testing.T, dir string) []policy.ControlDefinition {
	t.Helper()
	loader, err := ctlyaml.NewControlLoader()
	if err != nil {
		t.Fatalf("create control loader: %v", err)
	}
	controls, err := loader.LoadControls(context.Background(), dir)
	if err != nil {
		t.Skipf("load controls from %s: %v", dir, err)
	}
	return controls
}

func loadSnapshotsFromDir(t *testing.T, dir string) []asset.Snapshot {
	t.Helper()
	var snapshots []asset.Snapshot

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read observations: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join(dir, entry.Name()))
		if readErr != nil {
			t.Fatalf("read observation: %v", readErr)
		}
		var snap asset.Snapshot
		if jsonErr := json.Unmarshal(data, &snap); jsonErr != nil {
			t.Errorf("cannot unmarshal snapshot %s: %v", entry.Name(), jsonErr)
			continue
		}
		snapshots = append(snapshots, snap)
	}
	return snapshots
}
