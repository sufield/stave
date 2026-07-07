package stave_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sufield/stave/pkg/stave"
)

// TestApply_WithoutChainsDir is the drift-regression test: when
// Config.ChainsDir is empty (the library's default), the engine
// must not emit ChainFindings and per-finding ChainMembership must
// be nil. This matches the CLI's behavior when no chains directory
// is discoverable at its runtime root.
func TestApply_WithoutChainsDir(t *testing.T) {
	a, err := stave.Apply(context.Background(), stave.Config{
		SnapshotsDir: "../../testdata/e2e/e2e-h1-shopify-1021906/observations",
		ControlsDir:  "../../testdata/e2e/e2e-h1-shopify-1021906/controls",
		EvalTime:     time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(a.ChainFindings) != 0 {
		t.Errorf("ChainFindings without ChainsDir: want 0, got %d", len(a.ChainFindings))
	}
	for i := range a.Findings {
		if len(a.Findings[i].ChainMembership) != 0 {
			t.Errorf("Finding %d ChainMembership: want empty, got %d entries",
				i, len(a.Findings[i].ChainMembership))
		}
		// ChainBonus defaults to 1.0 when no chain matches.
		if a.Findings[i].ChainBonus != 1.0 {
			t.Errorf("Finding %d ChainBonus without chains: want 1.0, got %v",
				i, a.Findings[i].ChainBonus)
		}
	}
}

// TestApply_WithMatchingChain is the end-to-end surfacing test:
// when a chain definition matches the active catalog, the library
// surface populates Assessment.ChainFindings, per-finding
// ChainMembership, and ChainBonus. Uses a tmp chain directory with
// a hand-authored chain referencing CTL.S3.PUBLIC.001 + a synthetic
// second control so the escalation_threshold of 1 is trivially met.
//
// The purpose is verifying the library-boundary field-copying from
// internal types to pkg/stave types, not re-testing the engine's
// chain-matching logic (covered by chain_engine_test.go).
func TestApply_WithMatchingChain(t *testing.T) {
	tmp := t.TempDir()
	chainsDir := filepath.Join(tmp, "chains")
	if err := os.MkdirAll(chainsDir, 0o755); err != nil {
		t.Fatalf("mkdir chains: %v", err)
	}
	chainYAML := []byte(`id: public_read_path
description: Any public-read finding qualifies as a minimal compound-risk path.
controls:
  - CTL.S3.PUBLIC.001
  - CTL.S3.PUBLIC.002
escalation_threshold: 1
compound_severity: critical
preconditions:
  - iam_credential_theft
postconditions:
  - s3_data_access
`)
	if err := os.WriteFile(filepath.Join(chainsDir, "public_read_path.yaml"), chainYAML, 0o644); err != nil {
		t.Fatalf("write chain: %v", err)
	}

	a, err := stave.Apply(context.Background(), stave.Config{
		SnapshotsDir: "../../testdata/e2e/e2e-h1-shopify-1021906/observations",
		ControlsDir:  "../../testdata/e2e/e2e-h1-shopify-1021906/controls",
		ChainsDir:    chainsDir,
		EvalTime:     time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if len(a.ChainFindings) != 1 {
		t.Fatalf("ChainFindings: want 1, got %d", len(a.ChainFindings))
	}
	cf := a.ChainFindings[0]
	if cf.ChainID != "public_read_path" {
		t.Errorf("ChainID: got %q, want %q", cf.ChainID, "public_read_path")
	}
	if cf.Severity != stave.SeverityCritical {
		t.Errorf("Severity: got %q, want critical", cf.Severity)
	}

	// All matching findings must have ChainMembership populated and
	// ChainBonus = 1.5x (one chain).
	chainMemberCount := 0
	for i := range a.Findings {
		f := &a.Findings[i]
		if len(f.ChainMembership) == 0 {
			continue
		}
		chainMemberCount++
		if f.ChainBonus != 1.5 {
			t.Errorf("Finding %s ChainBonus: got %v, want 1.5", f.FindingID, f.ChainBonus)
		}
		// The ChainMembership entry's ChainID matches the ChainFinding's.
		if f.ChainMembership[0].ChainID != cf.ChainID {
			t.Errorf("ChainMembership mismatch: %q vs %q",
				f.ChainMembership[0].ChainID, cf.ChainID)
		}
	}
	if chainMemberCount == 0 {
		t.Errorf("expected at least one finding with ChainMembership populated")
	}
}

// TestApply_CrossAssetMarkerChainFires locks in that the
// cognito_unauth_phi_s3 chain composes a violation on a Cognito
// identity pool with a TypeMarker fact on a separately-collected
// PHI-tagged S3 bucket. This is the cross-asset path the audit's
// Experiment 1 originally — and wrongly — reported as broken; the
// chain actually fires end-to-end, the audit query just looked for
// chain data in the wrong JSON location (findings[].chain instead
// of the top-level chain_findings array).
//
// The test guards three layered assumptions:
//
//  1. The marker control (TypeMarker) fires on a bucket whose
//     properties.storage.tags.data-classification = "phi", with the
//     hyphenated key preserved through obs.v0.1 JSON load → CEL
//     activation → predicate evaluation.
//  2. The chain engine reads MarkerFindings as well as Findings
//     when bucketing failures (workflow.go intentionally appends
//     report.MarkerFindings into the failures slice it passes to
//     DetectChains).
//  3. The chain's scope_field (properties.identity.cognito.target_bucket_arn
//     on the Cognito asset) groups together with the S3 marker's
//     asset.ID fallback — because both resolve to the same bucket
//     ARN string, the engine puts both member findings in the same
//     scope bucket even though they live on different asset.IDs.
//
// A regression in any of those three would silently drop the
// HIPAA-reportable compound finding from the demo. Re-run before
// shipping any change to chain composition, marker partitioning,
// or property-path resolution.
func TestApply_CrossAssetMarkerChainFires(t *testing.T) {
	a, err := stave.Apply(context.Background(), stave.Config{
		SnapshotsDir: "../../examples/cognito-iteration2-unauth/fixtures/cross-resource-config/observations",
		ChainsDir:    "../../chains",
		EvalTime:     time.Date(2026, 5, 9, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// PHI marker must fire on the bucket — confirms hyphenated tag
	// key resolution. Without this, the chain has no second member
	// and never reaches its escalation threshold.
	var markerFired bool
	for i := range a.MarkerFindings {
		if a.MarkerFindings[i].ControlID == "CTL.S3.MARKER.PHI.001" {
			markerFired = true
			break
		}
	}
	if !markerFired {
		t.Fatalf("CTL.S3.MARKER.PHI.001 did not fire on PHI-tagged bucket; got %d markers", len(a.MarkerFindings))
	}

	// The cross-asset chain must compose the marker with the
	// Cognito-side violation.
	var chain *stave.ChainFinding
	for i := range a.ChainFindings {
		if a.ChainFindings[i].ChainID == "cognito_unauth_phi_s3" {
			chain = &a.ChainFindings[i]
			break
		}
	}
	if chain == nil {
		ids := make([]stave.ChainID, len(a.ChainFindings))
		for i := range a.ChainFindings {
			ids[i] = a.ChainFindings[i].ChainID
		}
		t.Fatalf("cognito_unauth_phi_s3 chain did not fire; chains seen: %v", ids)
	}
	if chain.Severity != stave.SeverityCritical {
		t.Errorf("chain severity: got %q, want %q", chain.Severity, stave.SeverityCritical)
	}

	foundMembers := make(map[stave.ControlID]struct{})
	for _, c := range chain.ControlsFailing {
		foundMembers[c] = struct{}{}
	}
	for _, c := range []stave.ControlID{
		"CTL.COGNITO.IDPOOL.UNAUTH.S3.001",
		"CTL.S3.MARKER.PHI.001",
	} {
		if _, ok := foundMembers[c]; !ok {
			t.Errorf("chain ControlsFailing missing expected member %q; got %v", c, chain.ControlsFailing)
		}
	}
}
