// Command s3-cross-account-replication-overperm is the CEL
// half of an iteration whose teaching point lives in the
// companion Z3 prover at z3prove/. The writeup that this
// example reverse-engineers
// (https://medium.com/p/seamless-cross-account-cross-region-
// replication-of-encrypted-objects-in-aws-s3) describes a
// working configuration that no checklist scanner flags as
// unsafe — but the bucket policy uses an account-root
// principal and `s3:Get*` / `s3:List*` action wildcards that
// admit far more than the author intended.
//
// This Go program runs Stave's full embedded control catalogue
// against both fixtures and reports how many findings each
// produces. The writeup config is *not* expected to fire any
// existing CEL control: the anti-pattern (account-root
// principal in a bucket policy, wildcard read actions) is not
// covered by Stave's built-in S3 catalogue today, which is
// itself the article's premise — checklist scanners say
// "clean."
//
// The Z3 prover at z3prove/ runs three queries against the
// same fixtures and returns SAT / SAT / UNSAT, naming the
// concrete witnesses for the two over-permissions and
// refuting one suspicion (KMS Resource:* in a key policy is
// correctly scoped to the key itself).
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

	// CEL side: run the full embedded catalogue against each
	// fixture and report findings count. The expectation is that
	// neither fixture fires anything — the writeup config and
	// the remediated config look identical to the catalogue's
	// existing posture controls. The Z3 prover at z3prove/ is
	// where the iteration's verdicts live.
	if phase == "writeup" || phase == "both" {
		runScenario(ctx, scenario{
			label: "writeup-config (account-root principal, s3:Get*/s3:List* wildcards)",
			dir:   filepath.Join(root, "fixtures/writeup-config/observations"),
			now:   now,
		})
	}
	if phase == "both" {
		fmt.Println()
	}
	if phase == "remediated" || phase == "both" {
		runScenario(ctx, scenario{
			label: "remediated-config (scoped Principal, AllowRead removed)",
			dir:   filepath.Join(root, "fixtures/remediated-config/observations"),
			now:   now,
		})
	}
	fmt.Println()
	fmt.Println("note: this CEL run is a foil — the over-permissions live")
	fmt.Println("      in shapes Stave's built-in catalogue does not catch.")
	fmt.Println("      Run z3prove/ for the formal proofs.")
}

type scenario struct {
	label string
	dir   string
	now   time.Time
}

func runScenario(ctx context.Context, s scenario) {
	root, _ := exampleRoot()
	cfg := stave.Config{
		SnapshotsDir:      s.dir,
		ControlsDir:       filepath.Join(root, "controls"),
		MaxUnsafe:         maxUnsafe,
		Now:               s.now,
		AllowUnknownInput: true,
	}
	a, err := stave.Apply(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] apply: %v\n", s.label, err)
		os.Exit(1)
	}

	fmt.Printf("=== %s ===\n", s.label)
	fmt.Printf("  status: %s   total_assets=%d   violations=%d\n",
		a.Status, a.Summary.TotalAssets, a.Summary.Violations)
	if len(a.Findings) == 0 {
		fmt.Printf("  no findings — Stave's built-in catalogue reports clean\n")
		return
	}
	fmt.Printf("  %d findings:\n", len(a.Findings))
	for _, f := range a.Findings {
		fmt.Printf("    - %s on %s (severity=%s)\n", f.ControlID, f.AssetID, f.Severity)
	}
}

func exampleRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("runtime.Caller(0) unavailable")
	}
	return filepath.Dir(file), nil
}
