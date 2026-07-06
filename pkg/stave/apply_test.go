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
// (Config.ControlsDir empty). The expected shape is foundational
// for both prototypes: 50 findings after asset-type gating + the
// collector's per-FindingID dedup, 26 Issues after consolidation,
// NON_COMPLIANT status. The numbers changed:
//
//   - 62/23 → 54/18 once ExceedsSLA was changed to strict-greater.
//   - 54 → 42 once the AssessmentCollector started deduplicating by
//     FindingID across RecordFindings calls (Phase 18).
//   - 42/18 → 38/14 once the prefix-exposure evaluator stopped
//     treating missing evidence as VIOLATION (now INCONCLUSIVE),
//     and INCOMPLETE controls gained applicable_asset_types scoping.
//   - 38/14 → 50/26 after new controls (EC2 account toggles,
//     expanded S3/SNS/SQS/Lambda policy families).
func TestApply_LordofheavenBuiltinControls(t *testing.T) {
	const wantFindings = 50
	const wantIssues = 26

	a, err := stave.Apply(context.Background(), stave.Config{
		SnapshotsDir: lordofheavenSnapshots,
		Now:          frozenNow,
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if got := len(a.Findings); got != wantFindings {
		t.Errorf("findings: got %d, want %d", got, wantFindings)
	}
	if got := len(a.Issues); got != wantIssues {
		t.Errorf("issues: got %d, want %d", got, wantIssues)
	}
	if a.Status != stave.StatusNonCompliant {
		t.Errorf("status: got %q, want %q", a.Status, stave.StatusNonCompliant)
	}
	if a.Summary.Violations != wantFindings {
		t.Errorf("summary.violations: got %d, want %d", a.Summary.Violations, wantFindings)
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

// TestApply_FamilyTemplateInheritance verifies that findings for controls
// without per-control triage overrides inherit infection/failure from
// their family template and get derived defects from predicate analysis.
func TestApply_FamilyTemplateInheritance(t *testing.T) {
	a, err := stave.Apply(context.Background(), stave.Config{
		SnapshotsDir: lordofheavenSnapshots,
		Now:          frozenNow,
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	var withDefect, withoutDefect int
	for _, f := range a.Findings {
		if f.Infection != "" {
			if f.Defect != "" {
				withDefect++
			} else {
				withoutDefect++
			}
		}
	}
	t.Logf("findings: %d with defect, %d with infection-only (no derivable defect)", withDefect, withoutDefect)

	for _, f := range a.Findings {
		if f.ControlID == "CTL.S3.PUBLIC.LIST.001" {
			if f.Infection == "" {
				t.Error("CTL.S3.PUBLIC.LIST.001 should inherit infection from CTL.S3 family template")
			}
			if f.Failure == "" {
				t.Error("CTL.S3.PUBLIC.LIST.001 should inherit failure from CTL.S3 family template")
			}
			if f.Defect == "" {
				t.Error("CTL.S3.PUBLIC.LIST.001 should have derived defect from predicate")
			}
			return
		}
	}
	t.Error("CTL.S3.PUBLIC.LIST.001 not found in findings")
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
