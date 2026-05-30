// Command staging-stale-endpoint demonstrates Stave's
// environment-tag-aware staleness control —
// CTL.LIFECYCLE.STAGING.STALE.001 — which extends the
// per-service dormancy controls (CloudFront LIFECYCLE.DORMANT,
// API Gateway ORPHAN.API, etc.) with an environment-tag
// dimension. Per-service controls fire on the lifecycle signal
// alone; this control fires only when a non-production tag
// (staging, dev, qa, sandbox, demo, ...) is also present.
//
// The example also demonstrates the EXPOSED compound — when
// CTL.LIFECYCLE.STAGING.STALE.001 fires together with a
// public-access control on the same asset, the chain
// `staging_endpoint_exposed` (chains/staging_endpoint_exposed.yaml)
// escalates compound severity to HIGH.
//
// # Four scenarios
//
//	stale-staging        — staging-tagged + dormant → fires
//	active-staging       — staging-tagged + active  → silent
//	prod-dormant         — production-tagged + dormant → silent (this is the negative test
//	                       that proves environment awareness; per-service controls
//	                       may still fire on the lifecycle signal alone)
//	stale-staging-public — non-prod + dormant + public → fires both STALE + S3.PUBLIC.LIST
//	                       which is the chain trigger
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
	staleControlID stave.ControlID = "CTL.LIFECYCLE.STAGING.STALE.001"
	s3PublicListID stave.ControlID = "CTL.S3.PUBLIC.LIST.002"

	fixedNow  = "2026-01-09T00:00:00Z"
	maxUnsafe = 168 * time.Hour
)

type scenario struct {
	label             string
	dir               string
	expectStaleFires  bool
	expectPublicFires bool
}

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

	controlsDir := filepath.Join(root, "controls")

	scenarios := []scenario{
		{
			label:             "stale-staging        (env=staging, appears_unused=true, last_deployment_days=247)",
			dir:               filepath.Join(root, "fixtures/stale-staging/observations"),
			expectStaleFires:  true,
			expectPublicFires: false,
		},
		{
			label:             "active-staging       (env=staging, appears_unused=false, last_deployment_days=8)",
			dir:               filepath.Join(root, "fixtures/active-staging/observations"),
			expectStaleFires:  false,
			expectPublicFires: false,
		},
		{
			label:             "prod-dormant         (env=production, appears_unused=true, last_deployment_days=247)",
			dir:               filepath.Join(root, "fixtures/prod-dormant/observations"),
			expectStaleFires:  false,
			expectPublicFires: false,
		},
		{
			label:             "stale-staging-public (env=demo, appears_unused=true, public_list=true)",
			dir:               filepath.Join(root, "fixtures/stale-staging-public/observations"),
			expectStaleFires:  true,
			expectPublicFires: true,
		},
	}

	allOK := true
	for i, s := range scenarios {
		if i > 0 {
			fmt.Println()
		}
		allOK = runScenario(ctx, controlsDir, now, s) && allOK
	}

	if !allOK {
		os.Exit(1)
	}
}

func runScenario(ctx context.Context, controlsDir string, now time.Time, s scenario) bool {
	cfg := stave.Config{
		SnapshotsDir: s.dir,
		ControlsDir:  controlsDir,
		MaxUnsafe:    maxUnsafe,
		Now:          now,
	}
	a, err := stave.Apply(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] apply: %v\n", s.label, err)
		return false
	}

	stale := a.FindingsForControl(staleControlID)
	pub := a.FindingsForControl(s3PublicListID)

	fmt.Printf("=== %s ===\n", s.label)
	fmt.Printf("  status: %s   total_assets=%d   violations=%d\n",
		a.Status, a.Summary.TotalAssets, a.Summary.Violations)
	fmt.Printf("  %s: %d finding(s)\n", staleControlID, len(stale))
	for _, f := range stale {
		fmt.Printf("    - %s   severity=%s\n", f.AssetID, f.Severity)
	}
	fmt.Printf("  %s:    %d finding(s)\n", s3PublicListID, len(pub))
	for _, f := range pub {
		fmt.Printf("    - %s   severity=%s\n", f.AssetID, f.Severity)
	}

	staleFired := len(stale) > 0
	pubFired := len(pub) > 0
	staleOK := staleFired == s.expectStaleFires
	pubOK := pubFired == s.expectPublicFires
	if !staleOK || !pubOK {
		fmt.Fprintf(os.Stderr, "  ASSERTION FAILED: stale=(got %v, want %v)  public=(got %v, want %v)\n",
			staleFired, s.expectStaleFires, pubFired, s.expectPublicFires)
		return false
	}
	chainTriggered := staleFired && pubFired
	fmt.Printf("  assertions: stale=%v public=%v chain_triggered=%v ✓\n",
		staleFired, pubFired, chainTriggered)
	return true
}

func exampleRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("runtime.Caller(0) unavailable")
	}
	return filepath.Dir(file), nil
}
