package apply

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// extractExitCode returns the exit code from a command error, or 0 if err is nil.
func extractExitCode(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	t.Fatalf("unexpected error: %v", err)
	return -1
}

// compareGoldenJSON compares stdout bytes against a golden JSON file if it exists.
// Fields that vary between dev builds and tagged releases (tool_version) are
// stripped before comparison so golden files don't need updating on each release.
func compareGoldenJSON(t *testing.T, goldenFile string, stdout []byte) {
	t.Helper()
	goldenData, err := os.ReadFile(goldenFile)
	if err != nil {
		t.Fatalf("golden file missing (must be committed): %s", goldenFile)
	}
	var golden, actual any
	if err := json.Unmarshal(goldenData, &golden); err != nil {
		t.Fatalf("golden file contains invalid JSON: %v", err)
	}
	if err := json.Unmarshal(stdout, &actual); err != nil {
		t.Fatalf("command stdout is not valid JSON: %v\noutput: %s", err, string(stdout))
	}
	stripStaveVersion(golden)
	stripStaveVersion(actual)
	goldenNorm, _ := json.Marshal(golden)
	actualNorm, _ := json.Marshal(actual)
	if !bytes.Equal(goldenNorm, actualNorm) {
		t.Errorf("output does not match golden file\ngot:\n%s\nwant:\n%s",
			string(stdout), string(goldenData))
	}
}

// stripStaveVersion removes run.tool_version from a parsed JSON value so that
// golden comparisons are not sensitive to the build version.
func stripStaveVersion(v any) {
	m, ok := v.(map[string]any)
	if !ok {
		return
	}
	if run, ok := m["run"].(map[string]any); ok {
		delete(run, "tool_version")
	}
}

// TestApplyProfileE2E runs e2e golden file tests for apply --profile aws-s3.
func TestApplyProfileE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: builds CLI binary and runs e2e golden-file checks")
	}
	_, filename, _, _ := runtime.Caller(0)
	projectRoot := filepath.Join(filepath.Dir(filename), "..", "..")

	binPath := filepath.Join(t.TempDir(), "stave-test")
	buildCmd := exec.Command("go", "build", "-o", binPath, "./cmd/stave")
	buildCmd.Dir = projectRoot
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build stave: %v\n%s", err, out)
	}

	testCases := []struct {
		name     string
		dir      string
		wantExit int
		wantViol int
	}{
		{"obs-public", "aws-s3-obs-public", 3, 6},
		{"obs-private", "aws-s3-obs-private", 3, 4},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			baseDir := filepath.Join(projectRoot, "testdata", "e2e", tc.dir)
			inputFile := filepath.Join(baseDir, "observations.json")
			goldenFile := filepath.Join(baseDir, "golden.json")

			if _, err := os.Stat(inputFile); err != nil {
				t.Fatalf("input file not found (testdata must be present in repo): %s", inputFile)
			}

			cmd := exec.Command(binPath,
				"apply",
				"--profile", "aws-s3",
				"--input", inputFile,
				"--now", "2026-01-15T00:00:00Z")
			cmd.Dir = projectRoot
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			exitCode := extractExitCode(t, cmd.Run())
			if exitCode != tc.wantExit {
				t.Errorf("exit code = %d, want %d\nstderr: %s", exitCode, tc.wantExit, stderr.String())
			}

			var output struct {
				Summary struct {
					Violations int `json:"violations"`
				} `json:"summary"`
			}
			if err := json.Unmarshal(stdout.Bytes(), &output); err != nil && tc.wantViol > 0 {
				t.Fatalf("failed to parse output JSON: %v\noutput: %s", err, stdout.String())
			}
			if output.Summary.Violations != tc.wantViol {
				t.Errorf("violations = %d, want %d", output.Summary.Violations, tc.wantViol)
			}

			compareGoldenJSON(t, goldenFile, stdout.Bytes())
		})
	}
}
