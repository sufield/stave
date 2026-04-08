package e2e_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestE2E discovers and runs all e2e test cases under testdata/e2e/.
// Each subdirectory is a test case with controls, observations, and expected output files.
//
// Usage:
//
//	go test ./e2e/ -run E2E            # all cases
//	go test ./e2e/ -run E2E/e2e-s3     # S3 cases only
//	go test ./e2e/ -run E2E/e2e-h1     # HackerOne cases only
//	go test -short ./e2e/ -run E2E     # S3 cases only (short mode)
func TestE2E(t *testing.T) {
	bin := buildBinary(t)
	root := findE2ERoot(t)

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read e2e directory: %v", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		t.Run(name, func(t *testing.T) {
			if testing.Short() && !strings.HasPrefix(name, "e2e-s3-") {
				t.Skip("skipping non-S3 case in short mode")
			}
			runE2ECase(t, bin, filepath.Join(root, name))
		})
	}
}

func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "stave")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/stave")
	cmd.Dir = findRepoRoot(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build stave binary: %v\n%s", err, out)
	}
	return bin
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("cannot find repo root (no go.mod found)")
		}
		dir = parent
	}
}

func findE2ERoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(findRepoRoot(t), "testdata", "e2e")
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("e2e root not found: %v", err)
	}
	return root
}

func runE2ECase(t *testing.T, bin, caseDir string) {
	t.Helper()

	ctlDir := filepath.Join(caseDir, "controls")
	obsDir := filepath.Join(caseDir, "observations")
	now := "2026-01-11T00:00:00Z"

	// Clean up generated output from previous runs
	os.RemoveAll(filepath.Join(caseDir, "outdir"))

	repoRoot := findRepoRoot(t)

	// Use paths relative to repo root (matches golden file expectations)
	relCaseDir, _ := filepath.Rel(repoRoot, caseDir)
	relCtlDir, _ := filepath.Rel(repoRoot, ctlDir)
	relObsDir, _ := filepath.Rel(repoRoot, obsDir)

	var cmd *exec.Cmd
	if cmdFile := filepath.Join(caseDir, "command.txt"); fileExists(cmdFile) {
		content := readFileTrimmed(t, cmdFile)
		content = strings.ReplaceAll(content, "$CASE_DIR", relCaseDir)
		parts := strings.Fields(content)
		cmd = exec.Command(bin, parts...)
	} else {
		args := []string{
			"apply",
			"--controls", relCtlDir,
			"--observations", relObsDir,
			"--max-unsafe", "168h",
			"--now", now,
		}
		if argsFile := filepath.Join(caseDir, "args.txt"); fileExists(argsFile) {
			extra := readFileTrimmed(t, argsFile)
			extra = strings.ReplaceAll(extra, "$CASE_DIR", relCaseDir)
			args = append(args, strings.Fields(extra)...)
		}
		cmd = exec.Command(bin, args...)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Dir = repoRoot

	exitCode := 0
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("exec error: %v", err)
		}
	}

	checkExitCode(t, caseDir, exitCode)
	checkStderrPattern(t, caseDir, stderr.String())

	out := stdout.Bytes()
	isJSON := len(out) > 0 && (out[0] == '{' || out[0] == '[')

	if isJSON {
		checkSummary(t, caseDir, out)
		checkFindingsCount(t, caseDir, out)
		checkInputHashes(t, caseDir, out)
		checkSourceEvidence(t, caseDir, out)
		checkFullOutput(t, caseDir, out)
		checkSARIF(t, caseDir, out)
	}

	checkGeneratedFile(t, caseDir)
}

// --- Assertions ---

func checkExitCode(t *testing.T, caseDir string, got int) {
	t.Helper()
	path := filepath.Join(caseDir, "expected.exit")
	if !fileExists(path) {
		return
	}
	want := readFileTrimmed(t, path)
	if fmt.Sprintf("%d", got) != want {
		t.Errorf("exit code = %d, want %s", got, want)
	}
}

func checkStderrPattern(t *testing.T, caseDir string, stderr string) {
	t.Helper()
	path := filepath.Join(caseDir, "expected.err.txt")
	if !fileExists(path) {
		return
	}
	pattern := readFileTrimmed(t, path)
	if !strings.Contains(strings.ToLower(stderr), strings.ToLower(pattern)) {
		t.Errorf("stderr missing pattern %q in:\n%s", pattern, stderr)
	}
}

func checkSummary(t *testing.T, caseDir string, stdout []byte) {
	t.Helper()
	path := filepath.Join(caseDir, "expected.summary.json")
	if !fileExists(path) {
		return
	}
	expected := canonicalJSON(t, readFileBytes(t, path))
	actual := extractJSONPath(t, stdout, "summary")
	if expected != actual {
		t.Errorf("summary mismatch\nexpected: %s\nactual:   %s", expected, actual)
	}
}

func checkFindingsCount(t *testing.T, caseDir string, stdout []byte) {
	t.Helper()
	path := filepath.Join(caseDir, "expected.findings.count")
	if !fileExists(path) {
		return
	}
	want := readFileTrimmed(t, path)
	got := countJSONArrayPath(t, stdout, "findings")
	if fmt.Sprintf("%d", got) != want {
		t.Errorf("findings count = %d, want %s", got, want)
	}
}

func checkInputHashes(t *testing.T, caseDir string, stdout []byte) {
	t.Helper()
	path := filepath.Join(caseDir, "expected.input_hashes.json")
	if !fileExists(path) {
		return
	}
	expected := canonicalJSON(t, readFileBytes(t, path))
	actual := extractJSONPath(t, stdout, "run", "input_hashes")
	if expected != actual {
		t.Errorf("input_hashes mismatch\nexpected: %s\nactual:   %s", expected, actual)
	}
}

func checkSourceEvidence(t *testing.T, caseDir string, stdout []byte) {
	t.Helper()
	path := filepath.Join(caseDir, "expected.source_evidence.json")
	if !fileExists(path) {
		return
	}
	expected := canonicalJSON(t, readFileBytes(t, path))
	var parsed map[string]any
	if err := json.Unmarshal(stdout, &parsed); err != nil {
		t.Fatalf("parse stdout: %v", err)
	}
	findings, _ := parsed["findings"].([]any)
	result := map[string]any{}
	for _, f := range findings {
		fm, _ := f.(map[string]any)
		ev, _ := fm["evidence"].(map[string]any)
		if se, ok := ev["source_evidence"]; ok {
			cid, _ := fm["control_id"].(string)
			result[cid] = se
		}
	}
	actual := marshalCanonical(t, result)
	if expected != actual {
		t.Errorf("source_evidence mismatch\nexpected: %s\nactual:   %s", expected, actual)
	}
}

func checkFullOutput(t *testing.T, caseDir string, stdout []byte) {
	t.Helper()
	path := filepath.Join(caseDir, "expected.out.json")
	if !fileExists(path) {
		return
	}
	filter := func(data []byte) string {
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatalf("parse JSON: %v", err)
		}
		delete(m, "extensions")
		if run, ok := m["run"].(map[string]any); ok {
			delete(run, "tool_version")
		}
		return marshalCanonical(t, m)
	}
	expected := filter(readFileBytes(t, path))
	actual := filter(stdout)
	if expected != actual {
		t.Errorf("full output mismatch\nexpected: %s\nactual:   %s", expected, actual)
	}
}

func checkSARIF(t *testing.T, caseDir string, stdout []byte) {
	t.Helper()
	path := filepath.Join(caseDir, "expected.out.sarif")
	if !fileExists(path) {
		return
	}
	filter := func(data []byte) string {
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatalf("parse SARIF: %v", err)
		}
		if runs, ok := m["runs"].([]any); ok && len(runs) > 0 {
			if run, ok := runs[0].(map[string]any); ok {
				if tool, ok := run["tool"].(map[string]any); ok {
					if driver, ok := tool["driver"].(map[string]any); ok {
						delete(driver, "version")
					}
				}
			}
		}
		return marshalCanonical(t, m)
	}
	expected := filter(readFileBytes(t, path))
	actual := filter(stdout)
	if expected != actual {
		t.Errorf("SARIF output mismatch")
	}
}

func checkGeneratedFile(t *testing.T, caseDir string) {
	t.Helper()
	pathFile := filepath.Join(caseDir, "expected.generated.path")
	hashFile := filepath.Join(caseDir, "expected.generated.sha256")
	if !fileExists(pathFile) || !fileExists(hashFile) {
		return
	}
	relPath := readFileTrimmed(t, pathFile)
	expectedHash := readFileTrimmed(t, hashFile)
	genPath := filepath.Join(caseDir, relPath)
	if _, err := os.Stat(genPath); err != nil {
		t.Errorf("generated file missing: %s", genPath)
		return
	}
	data, err := os.ReadFile(genPath)
	if err != nil {
		t.Fatalf("read generated file: %v", err)
	}
	actualHash := fmt.Sprintf("%x", sha256.Sum256(data))
	if actualHash != expectedHash {
		t.Errorf("generated file hash mismatch\nexpected: %s\nactual:   %s", expectedHash, actualHash)
	}
}

// --- Utilities ---

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func readFileTrimmed(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return strings.TrimSpace(string(data))
}

func readFileBytes(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func canonicalJSON(t *testing.T, data []byte) string {
	t.Helper()
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse JSON: %v", err)
	}
	return marshalCanonical(t, v)
}

func marshalCanonical(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal JSON: %v", err)
	}
	var parsed any
	json.Unmarshal(b, &parsed)
	sorted, _ := json.Marshal(parsed)
	return string(sorted)
}

func extractJSONPath(t *testing.T, data []byte, keys ...string) string {
	t.Helper()
	var current any
	if err := json.Unmarshal(data, &current); err != nil {
		t.Fatalf("parse JSON: %v", err)
	}
	for _, key := range keys {
		m, ok := current.(map[string]any)
		if !ok {
			t.Fatalf("expected object at key %q", key)
		}
		current = m[key]
	}
	return marshalCanonical(t, current)
}

func countJSONArrayPath(t *testing.T, data []byte, key string) int {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("parse JSON: %v", err)
	}
	arr, ok := m[key].([]any)
	if !ok {
		return 0
	}
	return len(arr)
}
