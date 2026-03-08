package fix

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/internal/safetyenvelope"
)

func saveFixLoopFlags() func() {
	saved := struct {
		beforeDir    string
		afterDir     string
		controlsDir  string
		maxUnsafe    string
		now          string
		allowUnknown bool
		outDir       string
	}{
		beforeDir:    fixLoopBeforeDir,
		afterDir:     fixLoopAfterDir,
		controlsDir:  fixLoopControlsDir,
		maxUnsafe:    fixLoopMaxUnsafe,
		now:          fixLoopNow,
		allowUnknown: fixLoopAllowUnknown,
		outDir:       fixLoopOutDir,
	}
	return func() {
		fixLoopBeforeDir = saved.beforeDir
		fixLoopAfterDir = saved.afterDir
		fixLoopControlsDir = saved.controlsDir
		fixLoopMaxUnsafe = saved.maxUnsafe
		fixLoopNow = saved.now
		fixLoopAllowUnknown = saved.allowUnknown
		fixLoopOutDir = saved.outDir
	}
}

func TestBuildFixLoopReport(t *testing.T) {
	report := buildFixLoopReport(
		safetyenvelope.Verification{
			Run: safetyenvelope.VerificationRunInfo{
				Now:             time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC),
				BeforeSnapshots: 2,
				AfterSnapshots:  2,
			},
			Summary: safetyenvelope.VerificationSummary{
				BeforeViolations: 2,
				AfterViolations:  1,
				Resolved:         1,
				Remaining:        1,
				Introduced:       0,
			},
		},
		7*24*time.Hour,
		fixLoopArtifacts{},
	)
	if report.Pass {
		t.Fatalf("expected report to fail when remaining findings exist")
	}
	if report.MaxUnsafe != "168h0m0s" {
		t.Fatalf("unexpected max_unsafe: %s", report.MaxUnsafe)
	}
	if report.Verification.Remaining != 1 {
		t.Fatalf("unexpected remaining count: %d", report.Verification.Remaining)
	}
}

func TestRunFixLoopWritesArtifacts(t *testing.T) {
	restore := saveFixLoopFlags()
	defer restore()

	fixture := testdataDir(t, "e2e-s3-verify")
	outDir := t.TempDir()

	fixLoopBeforeDir = filepath.Join(fixture, "before")
	fixLoopAfterDir = filepath.Join(fixture, "after")
	fixLoopControlsDir = filepath.Join(fixture, "controls")
	fixLoopMaxUnsafe = "168h"
	fixLoopNow = "2026-01-11T00:00:00Z"
	fixLoopOutDir = outDir
	fixLoopAllowUnknown = false

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	cmd.SetOut(&bytes.Buffer{})
	if err := runFixLoop(cmd, nil); err != nil {
		t.Fatalf("runFixLoop returned error: %v", err)
	}

	files := []string{
		"evaluation.before.json",
		"evaluation.after.json",
		"verification.json",
		"remediation-report.json",
	}
	for _, name := range files {
		path := filepath.Join(outDir, name)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %s to exist: %v", path, err)
		}
	}

	data, err := os.ReadFile(filepath.Join(outDir, "remediation-report.json"))
	if err != nil {
		t.Fatalf("read remediation report: %v", err)
	}
	var report fixLoopReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("parse remediation report: %v", err)
	}
	if !report.Pass {
		t.Fatalf("expected pass for e2e-s3-verify fixture, got fail: %s", report.Reason)
	}
	if report.Verification.Resolved == 0 {
		t.Fatalf("expected at least one resolved finding in remediation report")
	}
}
