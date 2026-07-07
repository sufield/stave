package cliapi_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/sufield/stave/pkg/stave"
	"github.com/sufield/stave/pkg/stave/cliapi"
)

// TestApply_ReturnsBothViews verifies the cliapi entry point surfaces
// both the trimmed *stave.Assessment and the raw *evaluation.ComplianceReport
// from a single evaluation pass. Uses the e2e-01-violation fixture so
// the test exercises the full pipeline end-to-end (snapshot load, control
// resolution, evaluation, reachability) rather than mocked components.
func TestApply_ReturnsBothViews(t *testing.T) {
	fixture := findFixture(t, "e2e-01-violation")
	cfg := stave.Config{
		SnapshotsDir: filepath.Join(fixture, "observations"),
		ControlsDir:  filepath.Join(fixture, "controls"),
		MaxUnsafe:    168 * time.Hour,
		// --eval-time matches cmd/apply test convention so evaluations
		// are deterministic and don't depend on wall clock.
		EvalTime: time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC),
	}

	res, err := cliapi.Apply(context.Background(), cfg)
	if err != nil {
		t.Fatalf("cliapi.Apply: %v", err)
	}

	if res.Assessment == nil {
		t.Fatal("ApplyResult.Assessment is nil")
	}
	if res.ComplianceReport == nil {
		t.Fatal("ApplyResult.ComplianceReport is nil")
	}

	// The two views must agree on the violation count — they were
	// produced by the same evaluation pass and any divergence
	// indicates a copy bug in BuildAssessment.
	if got, want := res.Assessment.Summary.Violations, res.ComplianceReport.Summary.Violations; got != want {
		t.Errorf("Violations: Assessment=%d, ComplianceReport=%d (must match)", got, want)
	}
	if got, want := len(res.Assessment.Findings), len(res.ComplianceReport.Findings); got != want {
		t.Errorf("Findings count: Assessment=%d, ComplianceReport=%d (must match)", got, want)
	}

	// e2e-01-violation fires exactly one finding by design — if the
	// fixture is regenerated to a different shape this test must be
	// updated. The point is that we observe the engine produced
	// findings, not an empty report.
	if len(res.Assessment.Findings) == 0 {
		t.Error("expected at least one finding from e2e-01-violation, got none")
	}

	// The internal report carries fields the public Assessment doesn't
	// surface — that's the whole point of cliapi. Spot-check one
	// (Run.MaxUnsafeDuration is internal-only on Run, the public
	// Run.MaxUnsafe is its time.Duration mirror).
	if res.ComplianceReport.Run.StaveVersion == "" {
		t.Error("ComplianceReport.Run.StaveVersion is empty — engine metadata not populated")
	}
}

// TestApply_RequiresSnapshotsDir verifies the validation guard. A
// caller that forgets to set SnapshotsDir should get a clear error
// rather than a panic from somewhere deep in the engine.
func TestApply_RequiresSnapshotsDir(t *testing.T) {
	_, err := cliapi.Apply(context.Background(), stave.Config{})
	if err == nil {
		t.Fatal("expected error for empty SnapshotsDir, got nil")
	}
}

// findFixture walks up from the test working directory to locate the
// repository's testdata/e2e/<name> directory. Test packages run with
// the package directory as cwd, so testdata/e2e is several levels up.
func findFixture(t *testing.T, name string) string {
	t.Helper()
	// pkg/stave/cliapi → testdata/e2e is three parents up.
	const rel = "../../../testdata/e2e"
	abs, err := filepath.Abs(filepath.Join(rel, name))
	if err != nil {
		t.Fatalf("resolve fixture path: %v", err)
	}
	return abs
}
