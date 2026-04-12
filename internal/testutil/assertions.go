// Package testutil provides shared test assertion helpers for the Stave codebase.
// All helpers call t.Helper() so failures report the caller's line number.
//
// This package uses google/go-cmp for structured comparison with readable diffs.
// Use the Assert* functions instead of reflect.DeepEqual for domain types.
package testutil

import (
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/trace"
)

// ---------------------------------------------------------------------------
// ComplianceReport assertions
// ---------------------------------------------------------------------------

// ReportOpts returns cmp.Options tuned for ComplianceReport comparison:
// - Ignores non-deterministic fields (Run.Now, timestamps)
// - Sorts findings and checks by control+asset ID for order-insensitive comparison
func ReportOpts() cmp.Options {
	return cmp.Options{
		cmpopts.IgnoreFields(evaluation.RunInfo{}, "Now", "StaveVersion"),
		cmpopts.IgnoreFields(evaluation.Evidence{}, "FirstUnsafeAt", "LastSeenUnsafeAt"),
		cmpopts.SortSlices(func(a, b evaluation.Finding) bool {
			if a.ControlID != b.ControlID {
				return a.ControlID < b.ControlID
			}
			return a.AssetID < b.AssetID
		}),
		cmpopts.SortSlices(func(a, b evaluation.ResourceCheck) bool {
			if a.ControlID != b.ControlID {
				return a.ControlID < b.ControlID
			}
			return a.AssetID < b.AssetID
		}),
	}
}

// AssertReportEqual compares two ComplianceReports, ignoring non-deterministic
// fields (timestamps, version) and normalizing sort order. Produces a readable
// diff on failure.
func AssertReportEqual(t *testing.T, want, got *evaluation.ComplianceReport) {
	t.Helper()
	if diff := cmp.Diff(want, got, ReportOpts()...); diff != "" {
		t.Errorf("ComplianceReport mismatch (-want +got):\n%s", diff)
	}
}

// AssertViolationCount verifies the report contains exactly n findings.
func AssertViolationCount(t *testing.T, got *evaluation.ComplianceReport, n int) {
	t.Helper()
	if len(got.Findings) != n {
		t.Errorf("findings: got %d, want %d", len(got.Findings), n)
	}
}

// AssertSecurityState verifies the report's security state.
func AssertSecurityState(t *testing.T, got *evaluation.ComplianceReport, want evaluation.SecurityState) {
	t.Helper()
	if got.SecurityState != want {
		t.Errorf("security state: got %s, want %s", got.SecurityState, want)
	}
}

// AssertFindingExists verifies a finding exists for the given control+asset pair.
func AssertFindingExists(t *testing.T, report *evaluation.ComplianceReport, controlID kernel.ControlID, assetID asset.ID) {
	t.Helper()
	f := report.GetFindingByResource(controlID, assetID)
	if f == nil {
		t.Errorf("missing finding for control=%s asset=%s", controlID, assetID)
	}
}

// ---------------------------------------------------------------------------
// LogicTrace assertions
// ---------------------------------------------------------------------------

// AssertTraceHasAssessment verifies the trace contains an assessment for
// the given resource and policy with the expected verdict.
func AssertTraceHasAssessment(t *testing.T, lt *trace.LogicTrace, resourceID, policyID, expectedVerdict string) {
	t.Helper()
	for i := range lt.Assessments {
		a := &lt.Assessments[i]
		if a.ResourceID == resourceID && a.PolicyID == policyID {
			if a.Verdict != expectedVerdict {
				t.Errorf("trace assessment %s×%s: verdict=%s, want %s",
					resourceID, policyID, a.Verdict, expectedVerdict)
			}
			return
		}
	}
	t.Errorf("trace missing assessment for resource=%s policy=%s", resourceID, policyID)
}

// AssertTraceStep verifies that an assessment's trace contains a step with
// the given name.
func AssertTraceStep(t *testing.T, assessment trace.Assessment, stepName string) {
	t.Helper()
	for i := range assessment.Steps {
		if assessment.Steps[i].Name == stepName {
			return
		}
	}
	t.Errorf("trace assessment %s×%s missing step %q",
		assessment.ResourceID, assessment.PolicyID, stepName)
}

// ---------------------------------------------------------------------------
// Time helpers
// ---------------------------------------------------------------------------

// FixedTime returns a deterministic timestamp for testing.
func FixedTime() time.Time {
	return time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
}

// ---------------------------------------------------------------------------
// Type-safe comparison helpers
// ---------------------------------------------------------------------------

// Diff returns a human-readable diff between two values using go-cmp.
// Returns "" if equal. Use with any comparable type.
func Diff[T any](want, got T, opts ...cmp.Option) string {
	return cmp.Diff(want, got, opts...)
}

// ---------------------------------------------------------------------------
// Sentinel error helpers
// ---------------------------------------------------------------------------

// These are re-exported from their home packages for test convenience.
// Tests can use: testutil.AssertErrorIs(t, err, integrity.ErrIntegrityViolation)

// AssertErrorIs verifies that err matches the target sentinel error.
func AssertErrorIs(t *testing.T, err, target error) {
	t.Helper()
	if err == nil {
		t.Errorf("expected error wrapping %v, got nil", target)
		return
	}
	if !errors.Is(err, target) {
		t.Errorf("error %v does not wrap %v", err, target)
	}
}

// AssertNoError fails the test if err is non-nil.
func AssertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
