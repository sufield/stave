// Command iam-overpermission-wildcard demonstrates Stave's
// library API against the iam-overpermission-wildcard
// invariant — a Lambda execution role whose attached policy
// grants `s3:*` on `*` when the function only needs
// `s3:GetObject` on one bucket prefix.
//
// CEL evaluation: does the unsafe state hold? The control
// reads the engine's pre-computed boolean
// (identity.policies.has_resource_wildcard_on_sensitive); the
// boolean rolls up the policy-statement walk into one verdict.
//
// The companion Z3 program at z3prove/ reads the raw policy
// statements directly and enumerates the specific dangerous
// actions the wildcard admits — Z3 produces the witness that
// turns "your policy is broad" into "your policy lets this
// role make this bucket public."
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
	invariantID stave.ControlID = "CTL.IAM.POLICY.RESOURCE.WILDCARD.001"

	fixedNow  = "2026-01-09T00:00:00Z"
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

	phase := "both"
	if len(os.Args) > 1 {
		phase = os.Args[1]
	}

	allOK := true
	if phase == "before" || phase == "both" {
		ok := runScenario(ctx, scenario{
			label:       "before (s3:* on *)",
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
			label:       "after  (scoped actions + ARNs)",
			dir:         filepath.Join(root, "fixtures/after/observations"),
			controlsDir: filepath.Join(root, "controls"),
			now:         now,
			expectFires: false,
		})
		allOK = allOK && ok
	}
	if phase == "both" {
		fmt.Println()
	}
	if phase == "bybit-pattern-before" || phase == "both" {
		ok := runScenario(ctx, scenario{
			label:       "bybit-pattern-before (s3:PutObject on company-frontend-*)",
			dir:         filepath.Join(root, "fixtures/bybit-pattern-before/observations"),
			controlsDir: filepath.Join(root, "controls"),
			now:         now,
			expectFires: false,
		})
		allOK = allOK && ok
	}
	if phase == "both" {
		fmt.Println()
	}
	if phase == "bybit-pattern-after" || phase == "both" {
		ok := runScenario(ctx, scenario{
			label:       "bybit-pattern-after  (read-only on prod, full on dev)",
			dir:         filepath.Join(root, "fixtures/bybit-pattern-after/observations"),
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

func exampleRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("runtime.Caller(0) unavailable")
	}
	return filepath.Dir(file), nil
}
