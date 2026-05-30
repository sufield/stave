// Command iam-autoscaling-privesc-bypass demonstrates Stave's
// library API against the iam-autoscaling-privesc-bypass
// invariant — the published 2022 EC2 Auto Scaling privesc
// research where a principal with the AWS-managed
// `DataScientist` policy + `AmazonElasticMapReduceFullAccess`
// policy + an explicit `DemoDenyPrivEscs` deny policy escalates
// to admin via `autoscaling:CreateLaunchConfiguration` +
// `autoscaling:CreateAutoScalingGroup` — a path the deny does
// not cover.
//
// CEL side: scoped to CTL.IAM.ESCALATE.PASSROLE.AUTOSCALING.001.
// The control reads
// properties.identity.escalation.passrole_autoscaling.present.
// On the writeup config that boolean is `true` (the engine's
// chain walker observes the path is open); the control fires.
// On the remediated config the deny is expanded to cover
// autoscaling actions; the boolean flips to `false` and the
// control is silent.
//
// The Z3 prover at z3prove/ does what CEL cannot: enumerate
// all 9 known compute-launch vectors against the deny coverage,
// proving the original deny covers 4 of 9 (and the remediated
// deny covers all 9), and surfacing the residual structural
// issue that iam:PassRole is scoped by service but not by
// resource — so any new compute service AWS adds becomes an
// immediate exploit path until the deny list is expanded again.
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

	phase := "all"
	if len(os.Args) > 1 {
		phase = os.Args[1]
	}

	fixtures := []struct {
		key   string
		label string
		dir   string
	}{
		{"writeup", "writeup-config (DataScientist + EMR + DenyPrivEscs)",
			filepath.Join(root, "fixtures/writeup-config/observations")},
		{"remediated", "remediated-config (deny expanded to all known compute-launch vectors)",
			filepath.Join(root, "fixtures/remediated-config/observations")},
	}

	allOK := true
	for i, f := range fixtures {
		if phase != "all" && phase != f.key {
			continue
		}
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
	fmt.Println("note: the CEL side checks one specific technique. The Z3 prover")
	fmt.Println("      enumerates 9 known compute-launch vectors and proves the")
	fmt.Println("      deny coverage gap explicitly, plus a residual finding the")
	fmt.Println("      remediated config does not close. Run z3prove/ for the full")
	fmt.Println("      verdict trail.")

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
		SnapshotsDir: s.dir,
		ControlsDir:  s.controlsDir,
		MaxUnsafe:    maxUnsafe,
		Now:          s.now,
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
