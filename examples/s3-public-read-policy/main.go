// Command s3-public-read-policy demonstrates Stave's library API
// against the s3-public-read-policy invariant.
//
// It loads two fixture snapshot directories — fixtures/before
// (vulnerable) and fixtures/after (remediated) — and asserts that
// CTL.S3.PUBLIC.001 fires on the first and is silent on the second.
//
// The example is intentionally narrow: it shows how a Go program
// composes pkg/stave's Apply + FindingsForControl helpers, with no
// CLI shelling out and no JSON unmarshaling. The article in
// channel/devto/ uses this binary's stdout verbatim.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/sufield/stave/pkg/stave"
)

const (
	invariantID  stave.ControlID = "CTL.S3.PUBLIC.001"
	exampleAsset stave.AssetID   = "arn:aws:s3:::acme-customer-uploads"

	// fixedNow pins the evaluator's clock so output stays
	// deterministic across runs and CI environments. The fixture's
	// snapshots span 2026-01-01 → 2026-01-08; this clock sits one
	// day past the latest snapshot.
	fixedNow = "2026-01-09T00:00:00Z"

	// maxUnsafe matches the CLI default; non-zero is required to
	// avoid pkg/stave's "coverage validator misconfigured" warning.
	maxUnsafe = 168 * time.Hour
)

func main() {
	root, err := exampleRoot()
	if err != nil {
		log.Fatalf("locate example root: %v", err)
	}

	ctx := context.Background()
	now, err := time.Parse(time.RFC3339, fixedNow)
	if err != nil {
		log.Fatalf("parse fixed now: %v", err)
	}

	// Phase selection lets each phase's stdout be captured to its
	// own expected/<phase>-output.txt so the article can show the
	// before / after blocks independently. Default ("both") runs
	// both for the standalone demo.
	phase := "both"
	if len(os.Args) > 1 {
		phase = os.Args[1]
	}

	allOK := true
	if phase == "before" || phase == "both" {
		ok := runScenario(ctx, scenario{
			label:       "before (vulnerable)",
			dir:         filepath.Join(root, "fixtures/before/observations"),
			controlsDir: filepath.Join(root, "controls"),
			now:         now,
			expectFires: true,
		})
		allOK = allOK && ok
	}
	if phase == "both" {
		fmt.Println()
	}
	if phase == "after" || phase == "both" {
		ok := runScenario(ctx, scenario{
			label:       "after  (remediated)",
			dir:         filepath.Join(root, "fixtures/after/observations"),
			controlsDir: filepath.Join(root, "controls"),
			now:         now,
			expectFires: false,
		})
		allOK = allOK && ok
	}

	if !allOK {
		os.Exit(1)
	}
}

type scenario struct {
	label       string
	dir         string
	controlsDir string
	now         time.Time
	expectFires bool
}

// runScenario evaluates one fixture directory and asserts whether
// the named invariant fires. Returns false (without exiting) when
// the assertion fails so main can report both scenarios before
// failing the run.
func runScenario(ctx context.Context, s scenario) bool {
	cfg := stave.Config{
		SnapshotsDir:      s.dir,
		ControlsDir:       s.controlsDir,
		MaxUnsafe:         maxUnsafe,
		Now:               s.now,
		AllowUnknownInput: true,
	}
	a, err := stave.Apply(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] apply: %v\n", s.label, err)
		return false
	}

	fmt.Printf("=== %s ===\n", s.label)
	fmt.Printf("  status: %s   total_assets=%d   violations=%d\n",
		a.Status, a.Summary.TotalAssets, a.Summary.Violations)

	matched := a.FindingsForControl(invariantID)
	if len(matched) == 0 {
		fmt.Printf("  %s: no findings\n", invariantID)
	} else {
		fmt.Printf("  %s fired on %d asset(s):\n", invariantID, len(matched))
		for _, f := range matched {
			fmt.Printf("    - %s   severity=%s   exposure_score=%.2f\n",
				f.AssetID, f.Severity, f.ExposureScore)
		}
	}

	fired := len(matched) > 0
	if fired != s.expectFires {
		fmt.Fprintf(os.Stderr, "  ASSERTION FAILED: expected fires=%v, got fires=%v\n",
			s.expectFires, fired)
		return false
	}
	fmt.Printf("  assertion: fires=%v (expected) ✓\n", fired)
	return true
}

// exampleRoot returns the directory containing this main.go,
// derived from runtime.Caller so the binary works regardless of
// invocation cwd: `go run ./examples/...` from stave/ and
// `cd examples/... && go run .` both resolve to the same root.
func exampleRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("runtime.Caller(0) unavailable")
	}
	return filepath.Dir(file), nil
}
