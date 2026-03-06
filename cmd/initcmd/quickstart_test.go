package initcmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestQuickstartNoSnapshotShowsSingleNextStep(t *testing.T) {
	tmp := t.TempDir()
	wd, wdErr := os.Getwd()
	if wdErr != nil {
		t.Fatalf("getwd: %v", wdErr)
	}
	defer func() { _ = os.Chdir(wd) }()
	if chdirErr := os.Chdir(tmp); chdirErr != nil {
		t.Fatalf("chdir: %v", chdirErr)
	}

	root := GetRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"quickstart"})

	if execErr := root.Execute(); execErr != nil {
		t.Fatalf("quickstart command failed: %v", execErr)
	}

	out := buf.String()
	if !strings.Contains(out, "Source: built-in demo fixture") {
		t.Fatalf("expected demo source output, got: %s", out)
	}
	if !strings.Contains(out, "Top finding: CTL.S3.PUBLIC.001") {
		t.Fatalf("expected first finding output, got: %s", out)
	}
	if !strings.Contains(out, "Report: stave-report.json") {
		t.Fatalf("expected report output, got: %s", out)
	}
	if !strings.Contains(out, "Next: run `stave demo --fixture known-good` to compare safe output.") {
		t.Fatalf("expected next-step output, got: %s", out)
	}
	if _, statErr := os.Stat(filepath.Join(tmp, "stave-report.json")); statErr != nil {
		t.Fatalf("expected report artifact: %v", statErr)
	}
	reportBytes, readErr := os.ReadFile(filepath.Join(tmp, "stave-report.json"))
	if readErr != nil {
		t.Fatalf("read report: %v", readErr)
	}
	var report map[string]any
	if parseErr := json.Unmarshal(reportBytes, &report); parseErr != nil {
		t.Fatalf("parse report json: %v", parseErr)
	}
	if got, ok := report["generated_at"].(string); !ok || got != "2026-01-15T00:00:00Z" {
		t.Fatalf("generated_at = %v, want 2026-01-15T00:00:00Z", report["generated_at"])
	}
}

func TestQuickstartDetectsObservationSnapshot(t *testing.T) {
	tmp := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer func() { _ = os.Chdir(wd) }()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	if err := os.WriteFile(filepath.Join(tmp, "snapshot.json"), demoSnapshotKnownBad, 0o644); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}

	root := GetRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"quickstart"})

	if err := root.Execute(); err != nil {
		t.Fatalf("quickstart command failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Source: ./snapshot.json") {
		t.Fatalf("expected source output, got: %s", out)
	}
	if !strings.Contains(out, "Top finding: CTL.S3.PUBLIC.001") {
		t.Fatalf("expected first finding output, got: %s", out)
	}
	if !strings.Contains(out, "Report: stave-report.json") {
		t.Fatalf("expected report output, got: %s", out)
	}
	if !strings.Contains(out, "Next: run `stave demo --fixture known-good` to compare safe output.") {
		t.Fatalf("expected next-step output, got: %s", out)
	}
	if _, err := os.Stat(filepath.Join(tmp, "stave-report.json")); err != nil {
		t.Fatalf("expected report artifact: %v", err)
	}
}

func TestQuickstartDetectsObservationSnapshotFromObservationsDir(t *testing.T) {
	tmp := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer func() { _ = os.Chdir(wd) }()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(tmp, "observations"), 0o755); err != nil {
		t.Fatalf("mkdir observations: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "observations", "snapshot.json"), demoSnapshotKnownBad, 0o644); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}

	root := GetRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"quickstart"})

	if err := root.Execute(); err != nil {
		t.Fatalf("quickstart command failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Source: ./observations/snapshot.json") {
		t.Fatalf("expected observations source output, got: %s", out)
	}
	if !strings.Contains(out, "Top finding: CTL.S3.PUBLIC.001") {
		t.Fatalf("expected first finding output, got: %s", out)
	}
}

func TestQuickstartInvalidObservationSnapshotFallsBackToDemo(t *testing.T) {
	tmp := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer func() { _ = os.Chdir(wd) }()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	// Looks like an observation snapshot but fails schema validation (missing vendor).
	invalid := []byte(`{"schema_version":"obs.v0.1","captured_at":"2026-01-15T00:00:00Z","resources":[{"id":"r1","type":"storage_bucket","properties":{}}],"identities":[]}`)
	if err := os.WriteFile(filepath.Join(tmp, "snapshot.json"), invalid, 0o644); err != nil {
		t.Fatalf("write invalid snapshot: %v", err)
	}

	root := GetRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"quickstart"})

	if err := root.Execute(); err != nil {
		t.Fatalf("quickstart command failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Source: built-in demo fixture") {
		t.Fatalf("expected demo fallback source output, got: %s", out)
	}
}

func TestQuickstartReportOverrideWritesCustomPath(t *testing.T) {
	tmp := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer func() { _ = os.Chdir(wd) }()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	reportPath := filepath.Join(tmp, "out", "quickstart-report.json")

	root := GetRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"quickstart", "--report", reportPath})

	if err := root.Execute(); err != nil {
		t.Fatalf("quickstart command failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Report: "+reportPath) {
		t.Fatalf("expected custom report output, got: %s", out)
	}
	if _, err := os.Stat(reportPath); err != nil {
		t.Fatalf("expected report artifact at custom path: %v", err)
	}
}

func TestQuickstartInvalidNowShowsRunHint(t *testing.T) {
	tmp := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer func() { _ = os.Chdir(wd) }()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	root := GetRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"quickstart", "--now", "not-a-time"})

	execErr := root.Execute()
	if execErr == nil {
		t.Fatal("expected quickstart to fail with invalid --now")
	}
	if !strings.Contains(execErr.Error(), "Run: stave quickstart --now 2026-01-15T00:00:00Z") {
		t.Fatalf("expected run hint, got: %v", execErr)
	}
}
