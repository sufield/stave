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
		"./before", "./after",
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
	fixture := testdataDir(t, "e2e-s3-verify")
	outDir := t.TempDir()

	flags := &fixLoopFlagsType{
		beforeDir:    filepath.Join(fixture, "before"),
		afterDir:     filepath.Join(fixture, "after"),
		controlsDir:  filepath.Join(fixture, "controls"),
		maxUnsafe:    "168h",
		now:          "2026-01-11T00:00:00Z",
		outDir:       outDir,
		allowUnknown: false,
	}

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	cmd.SetOut(&bytes.Buffer{})
	if err := runFixLoop(cmd, flags); err != nil {
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
