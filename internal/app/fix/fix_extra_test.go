package fix

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
)

// ---------------------------------------------------------------------------
// ValidateLoopDirs
// ---------------------------------------------------------------------------

func TestValidateLoopDirs_BadBefore(t *testing.T) {
	req := LoopRequest{
		BeforeDir:   "/nonexistent/path/before",
		AfterDir:    t.TempDir(),
		ControlsDir: t.TempDir(),
	}
	if err := ValidateLoopDirs(req); err == nil {
		t.Fatal("expected error for nonexistent before dir")
	}
}

func TestValidateLoopDirs_Valid(t *testing.T) {
	req := LoopRequest{
		BeforeDir:   t.TempDir(),
		AfterDir:    t.TempDir(),
		ControlsDir: t.TempDir(),
	}
	if err := ValidateLoopDirs(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// BuildReport
// ---------------------------------------------------------------------------

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

func TestBuildReport_Pass(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	verification := &report.Attestation{
		Summary: report.AttestationSummary{
			Open:        0,
			Regressions: 0,
		},
		Run: report.AttestationRunInfo{
			Now:             now,
			BeforeSnapshots: 2,
			AfterSnapshots:  2,
		},
	}
	req := LoopRequest{
		BeforeDir:         "/before",
		AfterDir:          "/after",
		MaxUnsafeDuration: 24 * time.Hour,
	}
	rpt := BuildReport(req, fixedClock{now}, verification, LoopArtifacts{})
	if !rpt.Passed {
		t.Fatal("expected pass")
	}
	if !strings.Contains(rpt.Reason, "resolved") {
		t.Fatalf("reason = %q", rpt.Reason)
	}
}

func TestBuildReport_Fail(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	verification := &report.Attestation{
		Summary: report.AttestationSummary{
			Open:        3,
			Regressions: 1,
		},
		Run: report.AttestationRunInfo{Now: now},
	}
	req := LoopRequest{
		BeforeDir:         "/before",
		AfterDir:          "/after",
		MaxUnsafeDuration: 24 * time.Hour,
	}
	rpt := BuildReport(req, fixedClock{now}, verification, LoopArtifacts{})
	if rpt.Passed {
		t.Fatal("expected fail")
	}
	if !strings.Contains(rpt.Reason, "remaining=3") {
		t.Fatalf("reason = %q", rpt.Reason)
	}
}

// ---------------------------------------------------------------------------
// NewArtifactWriter requires FileSystem
// ---------------------------------------------------------------------------

func TestNewArtifactWriter_NilFS(t *testing.T) {
	_, err := NewArtifactWriter("/out", WriteOptions{}, &bytes.Buffer{}, nil)
	if err == nil {
		t.Fatal("expected error for nil FileSystem")
	}
}

// ---------------------------------------------------------------------------
// ErrViolationsRemaining
// ---------------------------------------------------------------------------

func TestErrViolationsRemaining(t *testing.T) {
	if ErrViolationsRemaining.Error() == "" {
		t.Fatal("expected non-empty error message")
	}
}

// ---------------------------------------------------------------------------
// LoopReport schema version
// ---------------------------------------------------------------------------

func TestLoopReportSchemaVersion(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	rpt := BuildReport(LoopRequest{MaxUnsafeDuration: time.Hour}, fixedClock{now}, &report.Attestation{
		Run: report.AttestationRunInfo{Now: now},
	}, LoopArtifacts{})
	if rpt.SchemaVersion != kernel.SchemaFixLoop {
		t.Fatalf("schema = %v, want %v", rpt.SchemaVersion, kernel.SchemaFixLoop)
	}
	if rpt.Kind != kernel.KindRemediationReport {
		t.Fatalf("kind = %v, want %v", rpt.Kind, kernel.KindRemediationReport)
	}
}
