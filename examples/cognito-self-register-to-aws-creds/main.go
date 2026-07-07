// Command cognito-self-register-to-aws-creds is the CEL
// half of an iteration that proves the four-stage Cognito
// attack chain from Serj Novoselov's 2023 Medium writeup —
// self-register → self-promote → obtain identity-pool
// credentials → access AWS resources.
//
// CEL side: scoped to CTL.COGNITO.SELFREG.001 (one of the
// catalogue's per-technique Cognito governance controls).
// On the writeup config the boolean
// identity.governance.self_registration_restricted is
// false; the control fires. On the remediated config the
// boolean is true; silent.
//
// The Z3 prover at z3prove/ proves the full compound chain
// across user pool + app client + identity pool + IAM
// roles, plus a choke-point analysis showing which single
// configuration change breaks the entire chain.
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
	invariantID stave.ControlID = "CTL.COGNITO.SELFREG.001"

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

	fixtures := []struct {
		key   string
		label string
		dir   string
	}{
		{"writeup", "writeup-config (self-register + writable role attribute + unauth IDP + s3:* auth role)",
			filepath.Join(root, "fixtures/writeup-config/observations")},
		{"remediated", "remediated-config (admin-only create + scoped attrs + auth-only IDP + scoped roles)",
			filepath.Join(root, "fixtures/remediated-config/observations")},
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
			evalTime:    evalTime,
		})
		allOK = allOK && ok
	}
	fmt.Println()
	fmt.Println("note: this CEL run is one technique-level signal. The Z3")
	fmt.Println("      prover at z3prove/ runs the full four-stage chain")
	fmt.Println("      across user pool + app client + identity pool + IAM,")
	fmt.Println("      plus a choke-point analysis showing which single fix")
	fmt.Println("      collapses the entire chain.")

	if !allOK {
		os.Exit(1)
	}
}

type scenario struct {
	label       string
	dir         string
	controlsDir string
	evalTime    time.Time
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
