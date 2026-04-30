package apply

import (
	"bytes"
	"encoding/json"
	"errors"
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
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	t.Fatalf("unexpected error: %v", err)
	return -1
}

// compareGoldenJSON compares stdout bytes against a golden JSON file.
// The comparison strips run.tool_version and run.policy_fingerprint
// before comparing so golden files do not need updating on each
// release.
//
// These golden.json files are managed by the regengoldens tool, not
// by the in-process UPDATE_GOLDEN env var. To regenerate, run
// `make golden-fixture FILTER=aws-s3-obs` (or any matching regex).
// In-process UPDATE_GOLDEN is reserved for goldens whose write path
// is purely Go-marshalled output (see internal/testutil/golden.go);
// these fixtures' goldens are produced by running the stave binary,
// which the test builds with different ldflags than `make build`,
// so a byte-identical write from inside the test is not feasible.
func compareGoldenJSON(t *testing.T, goldenFile string, stdout []byte) {
	t.Helper()
	goldenData, err := os.ReadFile(goldenFile)
	if err != nil {
		t.Fatalf("golden file missing (run `make golden-fixture FILTER=%s` to create): %s",
			filepath.Base(filepath.Dir(goldenFile)), goldenFile)
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
		t.Errorf("output does not match golden file %s\nRun `make golden-fixture FILTER=%s` to update.\ngot:\n%s\nwant:\n%s",
			goldenFile, filepath.Base(filepath.Dir(goldenFile)), string(stdout), string(goldenData))
	}
}

// stripStaveVersion removes run.tool_version and run.policy_fingerprint
// from a parsed JSON value so that golden comparisons are not sensitive
// to the build version or catalog churn unrelated to the case under test.
func stripStaveVersion(v any) {
	m, ok := v.(map[string]any)
	if !ok {
		return
	}
	if run, ok := m["run"].(map[string]any); ok {
		delete(run, "tool_version")
		delete(run, "policy_fingerprint")
	}
}

// TestApplyProfileE2E runs e2e golden file tests for apply --profile aws-s3.
func TestApplyProfileE2E(t *testing.T) {
	t.Parallel()
	// These fixture goldens are managed by the regengoldens tool
	// (`make golden-fixture FILTER=...`), not by the in-process
	// UPDATE_GOLDEN env var. The CI "Regenerate goldens and sync"
	// step runs `make golden-update-all` with UPDATE_GOLDEN=1 across
	// the whole module; that target is for Go-marshalled in-process
	// goldens only, and running this binary-driven test under it
	// produced empty stdout / exit-code-0 false-positives that
	// looked like a CLI regression. Skip explicitly so the same
	// breakage cannot reappear in any future workflow that sets
	// UPDATE_GOLDEN=1.
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		t.Skip("skipping profile fixture-golden checks during UPDATE_GOLDEN (use `make golden-fixture FILTER=...`)")
	}
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
		name      string
		dir       string
		profile   string
		extraArgs []string
		wantExit  int
		wantViol  int
	}{
		// Counts updated post-collector dedup: identical FindingIDs
		// from overlapping strategies are now suppressed at record
		// time, so the visible violation total matches the unique
		// finding-ID count.
		{"obs-public", "aws-s3-obs-public", "aws-s3", nil, 3, 10},
		{"obs-private", "aws-s3-obs-private", "aws-s3", nil, 3, 2},
		{"hipaa-cross-domain", "e2e-hipaa-cross-domain", "hipaa", []string{"--include-all"}, 3, 32},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			baseDir := filepath.Join(projectRoot, "testdata", "e2e", tc.dir)
			inputFile := filepath.Join(baseDir, "observations.json")
			goldenFile := filepath.Join(baseDir, "golden.json")

			if _, err := os.Stat(inputFile); err != nil {
				t.Fatalf("input file not found (testdata must be present in repo): %s", inputFile)
			}

			args := []string{
				"apply",
				"--profile", tc.profile,
				"--input", inputFile,
				"--now", "2026-01-15T00:00:00Z",
			}
			args = append(args, tc.extraArgs...)

			cmd := exec.Command(binPath, args...)
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
