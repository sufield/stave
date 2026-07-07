// Command cloudtrail-stop-logging demonstrates Stave's
// library API against the cloudtrail-stop-logging invariant
// — the first action a competent attacker takes after
// gaining initial access in an AWS account: stop the audit
// trail so the rest of the campaign happens unobserved.
//
// MITRE ATT&CK T1562.008 ("Disable or Modify Cloud Logs").
//
// CEL only — this is a presence check (is_logging == false
// OR is_multi_region_trail == false), not a logic question.
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
	invariantID stave.ControlID = "CTL.CLOUDTRAIL.STOP.DETECT.001"

	fixedNow  = "2026-01-09T00:00:00Z"
	maxUnsafe = 168 * time.Hour
)

func main() {
	root, err := exampleRoot()
	if err != nil {
		log.Fatalf("locate example root: %v", err)
	}

	ctx := context.Background()
	evalTime, err := time.Parse(time.RFC3339, fixedNow)
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
			label:       "before (trail stopped)",
			dir:         filepath.Join(root, "fixtures/before/observations"),
			controlsDir: filepath.Join(root, "controls"),
			evalTime:    evalTime,
			expectFires: true,
		})
		allOK = allOK && ok
	}
	if phase == "both" {
		fmt.Println()
	}
	if phase == "after" || phase == "both" {
		ok := runScenario(ctx, scenario{
			label:       "after  (trail re-started)",
			dir:         filepath.Join(root, "fixtures/after/observations"),
			controlsDir: filepath.Join(root, "controls"),
			evalTime:    evalTime,
			expectFires: false,
		})
		allOK = allOK && ok
	}
	if phase == "both" {
		fmt.Println()
	}
	if phase == "data-events-before" || phase == "both" {
		ok := runScenario(ctx, scenario{
			label:       "data-events-before (mgmt logging on, data events off)",
			dir:         filepath.Join(root, "fixtures/data-events-before/observations"),
			controlsDir: filepath.Join(root, "controls"),
			evalTime:    evalTime,
			expectFires: false,
		})
		allOK = allOK && ok
	}
	if phase == "both" {
		fmt.Println()
	}
	if phase == "data-events-after" || phase == "both" {
		ok := runScenario(ctx, scenario{
			label:       "data-events-after  (data events scoped to sensitive buckets)",
			dir:         filepath.Join(root, "fixtures/data-events-after/observations"),
			controlsDir: filepath.Join(root, "controls"),
			evalTime:    evalTime,
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
	evalTime    time.Time
	expectFires bool
}

func runScenario(ctx context.Context, s scenario) bool {
	cfg := stave.Config{
		SnapshotsDir: s.dir,
		ControlsDir:  s.controlsDir,
		MaxUnsafe:    maxUnsafe,
		EvalTime:     s.evalTime,
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
