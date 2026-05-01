package cel

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/testutil"
)

// TestCELParallelEvaluation runs the CEL evaluator against all e2e fixtures
// and reports compile/eval failures. This validates that the CEL compiler
// produces results for all built-in controls.
func TestCELParallelEvaluation(t *testing.T) {
	t.Parallel()
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

// Thin wrappers around the package-level fixture cache. Multiple
// fixtures share controls/snapshots in the testdata tree, so caching
// at the directory level cuts disk I/O and YAML parsing time
// proportional to fixture-set size.
func loadControlsFromDir(t *testing.T, dir string) []policy.ControlDefinition {
	t.Helper()
	return testutil.LoadControlsFromDir(t, dir)
}

func loadSnapshotsFromDir(t *testing.T, dir string) []asset.Snapshot {
	t.Helper()
	return testutil.LoadSnapshotsFromDir(t, dir)
}
