// Command eks-aws-auth-template-injection demonstrates
// Stave's library API against the
// eks-aws-auth-template-injection invariant — a Kubernetes
// cluster whose AWS IAM Authenticator identity-mapping
// template substitutes {{AccessKeyID}}, a value drawn from
// client-controlled URL query parameters in the presigned
// STS GetCallerIdentity request.
//
// Disclosed as Kubernetes #1580493 in 2022. The fix is to
// substitute from server-derived fields (SessionName, role
// ARN) instead of from anything the client can influence.
//
// CEL only — this is a presence check ("the template uses
// {{AccessKeyID}}"). Z3 wouldn't add reasoning value over
// the boolean.
//
// # Vendor note
//
// The asset's `vendor` field is "kubernetes", not "aws"
// — even though the cluster runs on EKS. Stave's vendor
// filter consults the control's scope_tags
// (`[kubernetes, auth]` for this control) and the asset's
// vendor field; an asset tagged `vendor: "aws"` would be
// skipped by the K8s control. The existing
// e2e-h1-kubernetes-1580493 fixture used to mis-tag this
// as `vendor: "aws"` and silently dropped the asset; that
// fixture has been corrected in the same change that
// shipped this example.
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
	invariantID stave.ControlID = "CTL.K8S.AUTH.ACCESSKEYMAP.001"

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
			label:       "before ({{AccessKeyID}} template)",
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
			label:       "after  ({{SessionName}} + role ARN)",
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
