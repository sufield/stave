package stave_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/pkg/stave"
)

// lordofheavenSnapshots is the observation fixture both prototypes
// run against. Resolved relative to the test binary's package dir
// (pkg/stave) by the Go test runner.
const lordofheavenSnapshots = "../../testdata/e2e/e2e-disclosure-lordofheaven-2025/observations"

// frozenNow is the deterministic evaluation clock the prototypes
// and this test use. Matches the lordofheaven fixture's expected
// post-gate count.
var frozenNow = time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC)

// TestApply_LordofheavenBuiltinControls runs the library against
// the lordofheaven snapshot using the embedded builtin catalog
// (Config.ControlsDir empty). The expected shape is load-bearing
// for both prototypes: 54 findings after asset-type gating, 18
// Issues after consolidation, NON_COMPLIANT status.
func TestApply_LordofheavenBuiltinControls(t *testing.T) {
	a, err := stave.Apply(context.Background(), stave.Config{
		SnapshotsDir: lordofheavenSnapshots,
		Now:          frozenNow,
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if got := len(a.Findings); got != 54 {
		t.Errorf("findings: got %d, want 54", got)
	}
	if got := len(a.Issues); got != 18 {
		t.Errorf("issues: got %d, want 18", got)
	}
	if a.Status != stave.StatusNonCompliant {
		t.Errorf("status: got %q, want %q", a.Status, stave.StatusNonCompliant)
	}
	if a.Summary.Violations != 54 {
		t.Errorf("summary.violations: got %d, want 54", a.Summary.Violations)
	}

	// Bucket-intent's exit condition: CTL.S3.PUBLIC.001 must be
	// present with Classification == StateAssertion on the
	// writable buckets.
	found := false
	for _, f := range a.Findings {
		if f.ControlID != "CTL.S3.PUBLIC.001" {
			continue
		}
		if f.AssetID != "gov-writable-bucket-1" {
			continue
		}
		if f.Classification != stave.StateAssertion {
			t.Errorf("classification: got %q, want %q", f.Classification, stave.StateAssertion)
		}
		if f.Severity != stave.SeverityCritical {
			t.Errorf("severity: got %q, want %q", f.Severity, stave.SeverityCritical)
		}
		found = true
		break
	}
	if !found {
		t.Error("expected CTL.S3.PUBLIC.001 on gov-writable-bucket-1, not found")
	}
}

// TestApply_FailsWithoutSnapshotsDir confirms the library rejects a
// zero-value Config.
func TestApply_FailsWithoutSnapshotsDir(t *testing.T) {
	_, err := stave.Apply(context.Background(), stave.Config{})
	if err == nil {
		t.Fatal("expected error for empty SnapshotsDir, got nil")
	}
	if !strings.Contains(err.Error(), "SnapshotsDir") {
		t.Errorf("error should mention SnapshotsDir: %v", err)
	}
}

// TestApply_ReturnsTypedValues confirms that a consumer reading
// assessment fields gets the typed IDs the library promises — the
// core primitive-obsession reduction the package exists to deliver.
func TestApply_ReturnsTypedValues(t *testing.T) {
	a, err := stave.Apply(context.Background(), stave.Config{
		SnapshotsDir: lordofheavenSnapshots,
		Now:          frozenNow,
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(a.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	f := a.Findings[0]
	if f.ControlID == "" || f.AssetID == "" || f.Classification == "" {
		t.Errorf("expected non-zero typed IDs: cid=%q aid=%q cls=%q",
			f.ControlID, f.AssetID, f.Classification)
	}
}
