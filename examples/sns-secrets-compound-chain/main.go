// Command sns-secrets-compound-chain is the CEL half of an
// iteration that proves a four-service privilege escalation
// chain from a CloudGoat scenario (sns_secrets, July 2025
// VirajMathpati writeup): IAM user → SNS subscription →
// API Gateway invocation → Secrets Manager exfiltration.
//
// The CEL side is structurally a foil. The iteration's
// existing per-service control —
// CTL.SNS.POLICY.SUBSCRIBE.BROAD.001 — fires only when an
// SNS *topic policy* grants subscribe to broad principals.
// The writeup config doesn't have a topic policy at all
// (the IAM identity policy admits the subscription); the
// per-service control is silent. The four-service compound
// chain is what Z3 proves at z3prove/.
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
	invariantID stave.ControlID = "CTL.SNS.POLICY.SUBSCRIBE.BROAD.001"

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
		{"writeup", "writeup-config (cg-sns-user policy + bare topic + key-only API)",
			filepath.Join(root, "fixtures/writeup-config/observations")},
		{"remediated", "remediated-config (sns:Subscribe scoped + topic policy + IAM auth)",
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
			now:         now,
		})
		allOK = allOK && ok
	}
	fmt.Println()
	fmt.Println("note: this CEL run is a foil — the existing SNS topic-policy")
	fmt.Println("      control fires only when the topic itself has a broad")
	fmt.Println("      Subscribe grant. The writeup config has no topic policy")
	fmt.Println("      at all; the IAM identity policy admits the subscription.")
	fmt.Println("      The four-service chain is at z3prove/.")

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
