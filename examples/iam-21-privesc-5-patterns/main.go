// Command iam-21-privesc-5-patterns is the CEL half of an
// iteration that recasts Rhino Security Labs' canonical 21
// IAM privilege-escalation methods (Spencer Gietzen, 2018)
// as 5 structural Z3 patterns. The Z3 prover at z3prove/
// finds all 21 of Rhino's methods plus a comparable number
// of additional methods Rhino's manual enumeration didn't
// cover.
//
// The CEL side is a foil. Stave has 44+ per-technique IAM
// escalation controls; this example scopes to one
// (CTL.IAM.ESCALATE.PASSROLE.AUTOSCALING.001) to show that
// the CEL approach catches one method per control. Z3
// finds the *class* in one query.
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
	invariantID stave.ControlID = "CTL.IAM.ESCALATE.PASSROLE.AUTOSCALING.001"

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

	fixtures := []struct {
		key   string
		label string
		dir   string
	}{
		{"vulnerable", "rhino-vulnerable (all 21 Rhino methods enabled)",
			filepath.Join(root, "fixtures/rhino-vulnerable/observations")},
		{"partial-deny", "partial-deny (deny covers Rhino's 21 actions)",
			filepath.Join(root, "fixtures/partial-deny/observations")},
		{"remediated", "remediated (least-privilege)",
			filepath.Join(root, "fixtures/remediated/observations")},
		{"real-world-pattern3", "real-world-pattern3 (PassRole + RunInstances + compound network constraints)",
			filepath.Join(root, "fixtures/real-world-pattern3/observations")},
	}

	allOK := true
	for i, f := range fixtures {
		if i > 0 {
			fmt.Println()
		}
		ok := runScenario(ctx, scenario{
			label:       f.label,
			dir:         f.dir,
			controlsDir: filepath.Join(root, "controls"),
			now:         now,
		})
		allOK = allOK && ok
	}
	fmt.Println()
	fmt.Println("note: this CEL run is a foil — it scopes to one of Stave's")
	fmt.Println("      44+ per-technique IAM escalation controls. Each control")
	fmt.Println("      catches one method. The Z3 prover at z3prove/ recasts")
	fmt.Println("      Rhino's 21 manual enumerations as 5 structural queries")
	fmt.Println("      and finds methods Rhino didn't enumerate.")

	if !allOK {
		os.Exit(1)
	}
}

type scenario struct {
	label       string
	dir         string
	controlsDir string
	now         time.Time
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
		return true
	}
	fmt.Printf("  %s fired on %d asset(s):\n", invariantID, len(matched))
	for _, f := range matched {
		fmt.Printf("    - %s   severity=%s\n", f.AssetID, f.Severity)
	}
	return true
}

func exampleRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("runtime.Caller(0) unavailable")
	}
	return filepath.Dir(file), nil
}
