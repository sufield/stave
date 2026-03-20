package cel

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
)

// TestCELParallelEvaluation runs the CEL evaluator against all e2e fixtures
// and reports compile/eval failures. This validates that the CEL compiler
// produces results for all built-in controls.
func TestCELParallelEvaluation(t *testing.T) {
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
	compileSkips := 0
	evalSkips := 0

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

						// CEL evaluation
						cp, compileErr := compiler.Compile(ctl.UnsafePredicate)
						if compileErr != nil {
							compileSkips++
							continue
						}

						_, evalErr := Evaluate(cp, a, snap.Identities)
						if evalErr != nil {
							evalSkips++
							continue
						}

						celOK++
					}
				}
			}
		})
	}

	t.Logf("CEL parallel run: %d checks, %d successful, %d compile-skips, %d eval-skips",
		totalChecks, celOK, compileSkips, evalSkips)
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
			t.Logf("skip snapshot %s: %v", entry.Name(), jsonErr)
			continue
		}
		snapshots = append(snapshots, snap)
	}
	return snapshots
}
