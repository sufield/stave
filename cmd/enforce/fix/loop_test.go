package fix

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	appfix "github.com/sufield/stave/internal/app/fix"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/core/report"
	"github.com/sufield/stave/pkg/stave"
)

func TestBuildFixLoopReport(t *testing.T) {
	clock := ports.FixedClock(time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC))

	req := appfix.LoopRequest{
		BeforeDir:         "./before",
		AfterDir:          "./after",
		MaxUnsafeDuration: 7 * 24 * time.Hour,
	}
	v := report.Attestation{
		Run: report.AttestationRunInfo{
			EvalTime:        time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC),
			BeforeSnapshots: 2,
			AfterSnapshots:  2,
		},
		Summary: report.AttestationSummary{
			PreviousViolations: 2,
			CurrentViolations:  1,
			Remediated:         1,
			Open:               1,
			Regressions:        0,
		},
	}

	report := appfix.BuildReport(req, clock, &v, appfix.LoopArtifacts{})
	if report.Passed {
		t.Fatalf("expected report to fail when remaining findings exist")
	}
	if report.MaxUnsafeDuration != "168h0m0s" {
		t.Fatalf("unexpected max_unsafe: %s", report.MaxUnsafeDuration)
	}
	if report.Verification.Open != 1 {
		t.Fatalf("unexpected remaining count: %d", report.Verification.Open)
	}
}

func TestRunFixLoopWritesArtifacts(t *testing.T) {
	fixture := testdataDir(t, "e2e-s3-verify")
	outDir := t.TempDir()

	hasViolations, loopErr := stave.RunFixLoop(context.Background(), stave.FixLoopConfig{
		BeforeDir:   filepath.Join(fixture, "before"),
		AfterDir:    filepath.Join(fixture, "after"),
		ControlsDir: filepath.Join(fixture, "controls"),
		OutDir:      outDir,
		MaxUnsafe:   "168h",
		EvalTime:    "2026-01-11T00:00:00Z",
		Force:       true,
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if loopErr != nil {
		t.Fatalf("RunFixLoop returned error: %v", loopErr)
	}
	if hasViolations {
		t.Fatalf("expected no remaining violations for e2e-s3-verify fixture")
	}

	files := []string{
		"evaluation.before.json",
		"evaluation.after.json",
		"verification.json",
		"remediation-report.json",
	}
	for _, name := range files {
		path := filepath.Join(outDir, name)
		if _, statErr := os.Stat(path); statErr != nil {
			t.Fatalf("expected %s to exist: %v", path, statErr)
		}
	}

	data, err := os.ReadFile(filepath.Join(outDir, "remediation-report.json"))
	if err != nil {
		t.Fatalf("read remediation report: %v", err)
	}
	var report appfix.LoopReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("parse remediation report: %v", err)
	}
	if !report.Passed {
		t.Fatalf("expected pass for e2e-s3-verify fixture, got fail: %s", report.Reason)
	}
	if report.Verification.Remediated == 0 {
		t.Fatalf("expected at least one resolved finding in remediation report")
	}
}
