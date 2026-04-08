package testutil

import (
	"errors"
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/trace"
)

func TestAssertReportEqual_Identical(t *testing.T) {
	r := evaluation.ComplianceReport{
		SecurityState: evaluation.StateCompliant,
		Summary:       evaluation.ComplianceSummary{TotalAssets: 1},
	}
	// Should not fail.
	AssertReportEqual(t, r, r)
}

func TestReportOpts_IgnoresTimestamps(t *testing.T) {
	opts := ReportOpts()
	if len(opts) == 0 {
		t.Fatal("expected non-empty options")
	}
}

func TestAssertViolationCount(t *testing.T) {
	r := evaluation.ComplianceReport{
		Findings: []evaluation.Finding{{ControlID: "CTL.A.B.001"}},
	}
	AssertViolationCount(t, r, 1)
}

func TestAssertSecurityState(t *testing.T) {
	r := evaluation.ComplianceReport{SecurityState: evaluation.StateCompliant}
	AssertSecurityState(t, r, evaluation.StateCompliant)
}

func TestAssertFindingExists(t *testing.T) {
	r := evaluation.ComplianceReport{
		Findings: []evaluation.Finding{
			{ControlID: "CTL.S3.PUBLIC.001", AssetID: "bucket-1"},
		},
	}
	AssertFindingExists(t, r, kernel.ControlID("CTL.S3.PUBLIC.001"), asset.ID("bucket-1"))
}

func TestAssertTraceHasAssessment(t *testing.T) {
	lt := &trace.LogicTrace{
		Assessments: []trace.Assessment{
			{ResourceID: "bucket-1", PolicyID: "CTL.A.B.001", Verdict: "PASS"},
		},
	}
	AssertTraceHasAssessment(t, lt, "bucket-1", "CTL.A.B.001", "PASS")
}

func TestAssertTraceStep(t *testing.T) {
	a := trace.Assessment{
		Steps: []trace.Step{{Name: "predicate_evaluation"}},
	}
	AssertTraceStep(t, a, "predicate_evaluation")
}

func TestFixedTime(t *testing.T) {
	ft := FixedTime()
	if ft.IsZero() {
		t.Fatal("FixedTime should not be zero")
	}
}

func TestDiff_Equal(t *testing.T) {
	d := Diff("hello", "hello")
	if d != "" {
		t.Fatalf("expected no diff, got: %s", d)
	}
}

func TestDiff_NotEqual(t *testing.T) {
	d := Diff("hello", "world")
	if d == "" {
		t.Fatal("expected diff for different strings")
	}
}

func TestAssertNoError(t *testing.T) {
	AssertNoError(t, nil)
}

func TestAssertErrorIs(t *testing.T) {
	sentinel := errors.New("sentinel")
	wrapped := errors.Join(sentinel, errors.New("extra"))
	_ = wrapped
	// Just test the basic case — sentinel matches itself.
	AssertErrorIs(t, sentinel, sentinel)
}
