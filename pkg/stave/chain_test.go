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
		Now:          time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC),
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
		Now:          time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC),
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
	// ChainID is the typed alias — compile-time check passes if it's
	// assignment-compatible with stave.ChainID.
	var _ stave.ChainID = cf.ChainID
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
