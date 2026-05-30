// Command s3-bucket-name-dangling demonstrates Stave's library
// API against the s3-bucket-name-dangling pattern — a CDN origin
// (or DNS CNAME) that references an S3 bucket name no longer
// owned by the account.
//
// It loads two fixture snapshot directories — fixtures/before
// (dangling) and fixtures/after (claimed) — and asserts that
// CTL.S3.BUCKET.TAKEOVER.001 fires on the first and is silent on
// the second. Same shape as the other iteration examples.
//
// The asset type here is s3_bucket_reference, not aws_s3_bucket
// — the vulnerability lives in the *reference* (the DNS record /
// CDN origin / app config that points at S3), not in any bucket
// inside the account. This is the key modelling choice:
// scanners that inventory in-account buckets miss the pattern by
// design, because the unsafe state is precisely "no bucket
// exists with this name in this account."
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
	invariantID  stave.ControlID = "CTL.S3.BUCKET.TAKEOVER.001"
	exampleAsset stave.AssetID   = "acme-cdn-origin-assets"

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
			label:       "before (dangling)",
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
			label:       "after  (claimed)",
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

// exampleRoot returns the directory containing this main.go,
// derived from runtime.Caller so the binary works regardless of
// invocation cwd: `go run ./examples/...` from stave/ and
// `cd examples/... && go run .` both resolve to the same root.
func exampleRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("runtime.Caller(0) unavailable")
	}
	return filepath.Dir(file), nil
}
