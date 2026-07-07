// Command apigw-private-api-scoped-deny is the CEL half of
// an iteration whose teaching point lives in the companion
// Z3 prover at z3prove/.
//
// The writeup that this example reverse-engineers ("Securing
// Private APIs in API Gateway Using VPC Endpoints", Medium
// 2023) describes a private REST API restricted to one EC2
// host via a resource policy with `aws:sourceVpc` Deny
// condition. Stave's API Gateway control
// CTL.APIGATEWAY.NETWORK.PRIVATE.POLICY.001 fires only when
// `resource_policy_restricts_vpc == false` — i.e., when the
// private API has no VPC restriction at all. The writeup's
// config DOES restrict by VPC (just by the wrong dimension —
// VPC instead of VPC endpoint), so the boolean is `true` and
// the control is silent.
//
// The Z3 prover at z3prove/ runs four queries against the
// same fixtures and finds:
//   - Finding 1a (writeup-config):    UNSAT — Allow/Deny patterns aligned today
//   - Finding 1b (broadened-allow):   SAT   — one developer change opens it up
//   - Finding 2  (writeup-config):    SAT   — non-intended VPCe in the same VPC reaches the API
//   - Finding 3  (writeup-config):    SAT   — compound: no auth + VPC-wide
//   - All on remediated-config:       UNSAT
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
	invariantID stave.ControlID = "CTL.APIGATEWAY.NETWORK.PRIVATE.POLICY.001"

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

	phase := "all"
	if len(os.Args) > 1 {
		phase = os.Args[1]
	}

	fixtures := []struct {
		key   string
		label string
		dir   string
	}{
		{"writeup", "writeup-config (sourceVpc + identical Resource patterns)",
			filepath.Join(root, "fixtures/writeup-config/observations")},
		{"broadened", "broadened-allow (developer widens Allow)",
			filepath.Join(root, "fixtures/broadened-allow/observations")},
		{"remediated", "remediated-config (sourceVpce + aligned + IAM auth)",
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
			evalTime:    evalTime,
		})
		allOK = allOK && ok
	}
	fmt.Println()
	fmt.Println("note: this CEL run is a foil — the gaps live in shapes the")
	fmt.Println("      catalogue's CTL.APIGATEWAY.NETWORK.PRIVATE.POLICY.001")
	fmt.Println("      does not catch (the control fires only when the API has")
	fmt.Println("      no VPC restriction at all). Run z3prove/ for the formal")
	fmt.Println("      proofs.")

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
