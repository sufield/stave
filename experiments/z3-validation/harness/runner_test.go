package harness

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// writeFakeStave installs an executable script that stands in for the
// real `stave apply` subprocess. The body controls stdout and exit
// code so the test can drive the subprocess-boundary contracts that
// the real binary won't reproduce on demand.
func writeFakeStave(t *testing.T, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary test relies on a POSIX shell script")
	}
	path := filepath.Join(t.TempDir(), "fake-stave")
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatalf("write fake stave: %v", err)
	}
	return path
}

// TestRunStaveApply_RejectsEmptyOutputUnderCleanExit pins the
// subprocess-boundary contract (bug-1 class): exit 0 must carry the
// out.v0.1 JSON on stdout. Empty stdout under a clean exit must be
// surfaced as an error, not parsed into nil findings that the
// comparator would silently mark "agreed."
func TestRunStaveApply_RejectsEmptyOutputUnderCleanExit(t *testing.T) {
	binary := writeFakeStave(t, "#!/bin/sh\nexit 0\n")

	_, err := runStaveApply(context.Background(), binary, "", t.TempDir())
	if err == nil {
		t.Fatal("expected error when stave apply exits 0 with empty stdout, got nil")
	}
}

// TestRunStaveApply_RejectsEmptyOutputUnderFindingsExit covers the
// same contract on the findings path: exit 3 also promises JSON on
// stdout. Empty stdout under exit 3 is an upstream regression, not an
// empty findings set.
func TestRunStaveApply_RejectsEmptyOutputUnderFindingsExit(t *testing.T) {
	binary := writeFakeStave(t, "#!/bin/sh\nexit 3\n")

	_, err := runStaveApply(context.Background(), binary, "", t.TempDir())
	if err == nil {
		t.Fatal("expected error when stave apply exits 3 with empty stdout, got nil")
	}
}

// TestRunStaveApply_ParsesFindings is the happy path: a clean exit
// with a valid out.v0.1-shaped document yields the parsed findings.
func TestRunStaveApply_ParsesFindings(t *testing.T) {
	binary := writeFakeStave(t,
		"#!/bin/sh\nprintf '{\"findings\":[{\"control_id\":\"c1\",\"asset_id\":\"a1\"}]}'\nexit 3\n")

	findings, err := runStaveApply(context.Background(), binary, "", t.TempDir())
	if err != nil {
		t.Fatalf("runStaveApply: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ControlID != "c1" || findings[0].AssetID != "a1" || findings[0].Verdict != "FAIL" {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
}
