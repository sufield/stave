package fix

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	appfix "github.com/sufield/stave/internal/app/fix"
	"github.com/sufield/stave/internal/safetyenvelope"
	"github.com/sufield/stave/pkg/alpha/domain/ports"
)

func TestBuildFixLoopReport(t *testing.T) {
	clock := ports.FixedClock(time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC))

	req := appfix.LoopRequest{
		BeforeDir:         "./before",
		AfterDir:          "./after",
		MaxUnsafeDuration: 7 * 24 * time.Hour,
	}
	v := safetyenvelope.Verification{
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
	}

	report := appfix.BuildReport(req, clock, v, appfix.LoopArtifacts{})
	if report.Pass {
		t.Fatalf("expected report to fail when remaining findings exist")
	}
	if report.MaxUnsafeDuration != "168h0m0s" {
		t.Fatalf("unexpected max_unsafe: %s", report.MaxUnsafeDuration)
	}
	if report.Verification.Remaining != 1 {
		t.Fatalf("unexpected remaining count: %d", report.Verification.Remaining)
	}
}

func TestRunFixLoopWritesArtifacts(t *testing.T) {
	fixture := testdataDir(t, "e2e-s3-verify")
	outDir := t.TempDir()

	clock := ports.FixedClock(time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC))
	runner := NewRunner(compose.NewDefaultProvider(), clock)
	runner.FileOptions = cmdutil.FileOptions{
		Overwrite: true,
		DirPerms:  0o700,
	}

	loopErr := runner.Loop(context.Background(), LoopRequest{
		BeforeDir:         filepath.Join(fixture, "before"),
		AfterDir:          filepath.Join(fixture, "after"),
		ControlsDir:       filepath.Join(fixture, "controls"),
		OutDir:            outDir,
		MaxUnsafeDuration: 168 * time.Hour,
		AllowUnknown:      false,
		Stdout:            &bytes.Buffer{},
		Stderr:            &bytes.Buffer{},
	})
	if loopErr != nil {
		t.Fatalf("Loop returned error: %v", loopErr)
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
	if !report.Pass {
		t.Fatalf("expected pass for e2e-s3-verify fixture, got fail: %s", report.Reason)
	}
	if report.Verification.Resolved == 0 {
		t.Fatalf("expected at least one resolved finding in remediation report")
	}
}
