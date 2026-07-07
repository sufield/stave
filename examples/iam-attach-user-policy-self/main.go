// Command iam-attach-user-policy-self demonstrates Stave's
// library API against the iam-attach-user-policy-self
// invariant — Rhino Security Labs' privilege-escalation
// technique #1: a user with `iam:AttachUserPolicy` whose
// Resource includes its own ARN can attach
// `arn:aws:iam::aws:policy/AdministratorAccess` to itself
// with a single API call and become admin.
//
// CEL evaluation: does the unsafe state hold? The control
// reads
// properties.identity.escalation.attach_user_policy_self.present
// — a boolean rolled up by the engine.
//
// The companion Z3 program at z3prove/ reads the raw policy
// statements directly and identifies the specific managed
// policy whose attachment turns the user into an admin.
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
	invariantID stave.ControlID = "CTL.IAM.ESCALATE.ATTACHUSERPOLICY.001"

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
			label:       "before (self-attach allowed)",
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
			label:       "after  (self-attach removed)",
			dir:         filepath.Join(root, "fixtures/after/observations"),
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
