package initcmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDemoKnownBadProducesSingleFindingAndReport(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	tmp := t.TempDir()
	defer func() { _ = os.Chdir(wd) }()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	reportPath := filepath.Join(tmp, "stave-report.json")
	root := GetRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"demo", "--fixture", "known-bad", "--report", reportPath})

	if err := root.Execute(); err != nil {
		t.Fatalf("demo command failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Found 1 violation: CTL.S3.PUBLIC.001") {
		t.Fatalf("expected single violation output, got: %s", out)
	}
	if !strings.Contains(out, "Asset: s3://demo-public-bucket") {
		t.Fatalf("expected resource line, got: %s", out)
	}
	if !strings.Contains(out, "Evidence: BlockPublicAccess=false, ACL=public-read") {
		t.Fatalf("expected evidence line, got: %s", out)
	}
	if _, err := os.Stat(reportPath); err != nil {
		t.Fatalf("expected report file at %s: %v", reportPath, err)
	}
}

func TestDemoKnownGoodProducesZeroViolations(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	tmp := t.TempDir()
	defer func() { _ = os.Chdir(wd) }()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	root := GetRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"demo", "--fixture", "known-good"})

	if err := root.Execute(); err != nil {
		t.Fatalf("demo command failed: %v", err)
	}
	if !strings.Contains(buf.String(), "Found 0 violations.") {
		t.Fatalf("expected zero violation output, got: %s", buf.String())
	}
}

func TestDemoInvalidNowShowsRunHint(t *testing.T) {
	root := GetRootCmd()
	root.SetOut(new(bytes.Buffer))
	root.SetErr(new(bytes.Buffer))
	root.SetArgs([]string{"demo", "--now", "not-a-time"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected demo to fail with invalid --now")
	}
	if !strings.Contains(err.Error(), "Run: stave demo --now 2026-01-15T00:00:00Z") {
		t.Fatalf("expected run hint, got: %v", err)
	}
}
