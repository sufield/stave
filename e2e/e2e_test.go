package e2e_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const e2eCaseTimeout = 90 * time.Second

// TestE2E discovers and runs all e2e test cases under testdata/e2e/.
// Each subdirectory is a test case with controls, observations, and expected output files.
//
// Usage:
//
//	go test ./e2e/ -run E2E            # all cases
//	go test ./e2e/ -run E2E/e2e-s3     # S3 cases only
//	go test ./e2e/ -run E2E/e2e-h1     # HackerOne cases only
//	go test -short ./e2e/              # skipped (e2e is CI-only)
func TestE2E(t *testing.T) {
	// Cases run serially. Each case spawns the stave binary and
	// exercises real CLI plumbing (filesystem, schema loaders,
	// engine); running them concurrently produced two distinct
	// failure modes on CI:
	//   - "thundering herd" CPU/I/O contention that stretched
	//     per-case runtime well past the 90s e2eCaseTimeout
	//   - filesystem-isolation hazards (shared temp dirs, config
	//     paths) that produced exec.CommandContext().Run() hangs
	//     waiting on locked files
	// Serial execution makes total suite time the sum of individual
	// cases — predictable and well-bounded by the package timeout.
	// CI also passes -parallel 1 as a belt-and-braces override.
	//
	// The package-level go test timeout in CI is 60m to absorb the
	// serial cost over ~5800 fixtures (the prior 30m / 45m budgets
	// were tight; the buffer prevents a transient slow build from
	// flipping the suite red). Each case still has its own 90s
	// e2eCaseTimeout enforced via context.WithTimeout in
	// runE2ECase.
	if testing.Short() {
		t.Skip("skipping e2e tests in short mode (CI-only — see Makefile test-ci target)")
	}
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
			// Heartbeat logs frame each subtest so a CI timeout points
			// at exactly the case that hung. Without these, the
			// package-level timeout fires after the cumulative budget
			// expires and the log shows the *next* unstarted case
			// rather than the one actually wedged. Visible only with
			// -v (CI sets it; local runs without -v stay quiet).
			//
			// The deferred banner closes the loop on the failure side:
			// when an assertion inside runE2ECase calls t.Errorf /
			// t.Fatalf, CI logs otherwise show many PASSes, generic
			// `--- ERROR ---` separators, and a package-level FAIL —
			// with no clear indicator of WHICH fixture went red. The
			// `>>> FAILED E2E CASE:` marker is grep-friendly and ties
			// the failure to a specific case directory.
			t.Logf(">>> STARTING E2E CASE: %s", name)
			defer func() {
				if t.Failed() {
					t.Logf(">>> FAILED E2E CASE: %s", name)
					// Mirror the failure marker to raw stderr.
					// `t.Logf` output is associated with the
					// subtest scope and Go's `go test` formatter
					// may interleave it under `--- FAIL: ...` /
					// `--- PASS: ...` headers in ways that make
					// the failing case hard to spot when CI logs
					// are dominated by PASS noise. Writing
					// directly to stderr produces a line outside
					// the subtest framing, so a CI scan for
					// `>>> FAILED E2E CASE:` always finds the
					// case name regardless of the surrounding
					// PASS volume. Only emitted on failure to
					// keep the happy-path log quiet.
					fmt.Fprintf(os.Stderr, ">>> FAILED E2E CASE: %s\n", name)
				} else {
					t.Logf(">>> COMPLETED E2E CASE: %s", name)
				}
			}()
			runE2ECase(t, bin, filepath.Join(root, name))
		})
	}
}

func buildBinary(t *testing.T) string {
	t.Helper()
	repoRoot := findRepoRoot(t)

	cmd := exec.Command("make", "build")
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make build: %v\n%s", err, out)
	}

	bin := filepath.Join(repoRoot, "stave")
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("built binary not found at %s: %v", bin, err)
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

	ctx, cancel := context.WithTimeout(context.Background(), e2eCaseTimeout)
	defer cancel()

	var cmd *exec.Cmd
	if cmdFile := filepath.Join(caseDir, "command.txt"); fileExists(cmdFile) {
		content := readFileTrimmed(t, cmdFile)
		content = strings.ReplaceAll(content, "$CASE_DIR", relCaseDir)
		parts := strings.Fields(content)
		cmd = exec.CommandContext(ctx, bin, parts...)
	} else {
		args := []string{
			"apply",
			"--controls", relCtlDir,
			"--observations", relObsDir,
			"--max-unsafe", "168h",
			"--eval-time", now,
		}
		// The apply command's default --format flipped from json to
		// text in commit 028ecab58 for human-readable first-run UX.
		// E2E fixtures that ship JSON-shaped expectations (built
		// before the flip) carry no `--format json` in args.txt
		// because they relied on the old default. Inject it here so
		// fixture intent (expressed by the presence of expected JSON
		// goldens) drives the CLI invocation, instead of asking
		// every fixture's args.txt to repeat the same flag. Text /
		// SARIF cases override the invocation via command.txt and
		// never reach this branch.
		if expectsJSONStdout(caseDir) && !argsContainFormat(caseDir) {
			args = append(args, "--format", "json")
		}
		if argsFile := filepath.Join(caseDir, "args.txt"); fileExists(argsFile) {
			extra := readFileTrimmed(t, argsFile)
			extra = strings.ReplaceAll(extra, "$CASE_DIR", relCaseDir)
			args = append(args, strings.Fields(extra)...)
		}
		cmd = exec.CommandContext(ctx, bin, args...)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Dir = repoRoot

	// Echo the exact invocation under -v so a failure in CI shows the
	// command line without forcing the reader to derive it from the
	// case dir. cmd.Args[0] is the binary path; [1:] is the flag set.
	t.Logf("running case=%s cmd=%s %s",
		filepath.Base(caseDir), bin, strings.Join(cmd.Args[1:], " "))

	// Run stave in its own process group so a context-deadline kill
	// also reaches any helpers it might fork. Without this, exec.Cmd's
	// SIGKILL hits only the immediate child; a grandchild that inherits
	// stdout keeps the pipe open and hangs cmd.Run() past ctx
	// cancellation, surfacing as a package-level timeout (the os/exec
	// watchCtx stack frame) rather than the per-case t.Fatalf below.
	setProcessGroup(cmd)

	exitCode := 0
	runErr := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		killProcessGroup(cmd)
		t.Fatalf(
			"e2e case timed out after %s\ncase: %s\nstdout:\n%s\nstderr:\n%s",
			e2eCaseTimeout, caseDir, stdout.String(), stderr.String(),
		)
	}
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("exec error: %v\nstdout:\n%s\nstderr:\n%s", runErr, stdout.String(), stderr.String())
		}
	}

	checkExitCode(t, caseDir, exitCode, stdout.Bytes(), stderr.Bytes())
	checkStderrPattern(t, caseDir, stderr.String())

	// TrimSpace handles leading newlines / whitespace before
	// the JSON root; without it a stray "\n" in stdout flips
	// isJSON to false and silently skips every JSON validator
	// below, masking the real cause when CI surfaces the case
	// as a vague package-level FAIL.
	out := bytes.TrimSpace(stdout.Bytes())

	expectsJSON := expectsJSONStdout(caseDir)

	isJSON := len(out) > 0 && (out[0] == '{' || out[0] == '[')

	if expectsJSON && !isJSON {
		// Turn fixture intent into a hard assertion. A case
		// that ships expected.* JSON files but produces empty
		// or non-JSON stdout is broken; failing here with the
		// case path + truncated stdout/stderr makes the
		// failing fixture obvious instead of letting the harness
		// silently skip validation and surface a vague
		// package-level failure later.
		t.Fatalf(
			"case %s: expected JSON output but got non-JSON/empty stdout\nstdout:\n%s\nstderr:\n%s",
			caseDir, truncate(stdout.Bytes(), 4096), truncate(stderr.Bytes(), 4096),
		)
	}

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
//
// Failure-handling rule for the helpers below: a fixture mismatch is
// definitively broken — there is no scenario where it makes sense to
// keep validating the rest of the case after the binary exited with
// the wrong code, the wrong JSON, or wrote the wrong file. Use
// t.Fatalf so the failure aborts the subtest immediately and the
// CI log surfaces the exact case + expected-file path instead of a
// trailing package-level "FAIL" with no signal. Each message is
// prefixed with the fixture's case directory AND the specific
// expected.* file that drove the assertion so the operator can
// inspect or regenerate the artifact directly.

func checkExitCode(t *testing.T, caseDir string, got int, stdout, stderr []byte) {
	t.Helper()
	path := filepath.Join(caseDir, "expected.exit")
	if !fileExists(path) {
		return
	}
	want := readFileTrimmed(t, path)
	if strconv.Itoa(got) != want {
		// Include caseDir + the expected.exit path so a CI log
		// pinpoints both the failing fixture and the file that
		// drove the comparison. Stdout / stderr show the actual
		// stave error message instead of just "exit 2 want 0".
		t.Fatalf("case %s: exit code = %d, want %s (from %s)\nstdout:\n%s\nstderr:\n%s",
			caseDir, got, want, path, truncate(stdout, 4096), truncate(stderr, 4096))
	}
}

// truncate caps a byte slice at n bytes for log output, replacing the
// tail with a "(...truncated)" marker. Stave error frames can be
// chatty; without this a single failing case can flood the CI log.
func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "\n(...truncated " + strconv.Itoa(len(b)-n) + " bytes)"
}

func checkStderrPattern(t *testing.T, caseDir string, stderr string) {
	t.Helper()
	path := filepath.Join(caseDir, "expected.err.txt")
	if !fileExists(path) {
		return
	}
	pattern := readFileTrimmed(t, path)
	if !strings.Contains(strings.ToLower(stderr), strings.ToLower(pattern)) {
		t.Fatalf("case %s: stderr missing pattern %q (from %s) in:\n%s",
			caseDir, pattern, path, stderr)
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
		t.Fatalf("case %s: summary mismatch against %s\nexpected: %s\nactual:   %s",
			caseDir, path, expected, actual)
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
	if strconv.Itoa(got) != want {
		t.Fatalf("case %s: findings count = %d, want %s (from %s)",
			caseDir, got, want, path)
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
		t.Fatalf("case %s: input_hashes mismatch against %s\nexpected: %s\nactual:   %s",
			caseDir, path, expected, actual)
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
		t.Fatalf("case %s: parse stdout: %v", caseDir, err)
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
		t.Fatalf("case %s: source_evidence mismatch against %s\nexpected: %s\nactual:   %s",
			caseDir, path, expected, actual)
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
			t.Fatalf("case %s: parse JSON: %v", caseDir, err)
		}
		delete(m, "extensions")
		delete(m, "generated_at")
		delete(m, "timestamp")
		if run, ok := m["run"].(map[string]any); ok {
			delete(run, "tool_version")
			delete(run, "policy_fingerprint")
			delete(run, "started_at")
			delete(run, "finished_at")
			delete(run, "duration_ms")
			delete(run, "duration")
			delete(run, "repo_sha")
			delete(run, "git_sha")
			delete(run, "environment")
			delete(run, "hostname")
		}
		return marshalCanonical(t, m)
	}
	expected := filter(readFileBytes(t, path))
	actual := filter(stdout)
	if expected != actual {
		t.Fatalf("case %s: full output mismatch against %s\nexpected: %s\nactual:   %s",
			caseDir, path, expected, actual)
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
			t.Fatalf("case %s: parse SARIF: %v", caseDir, err)
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
		t.Fatalf("case %s: SARIF output mismatch against %s\nexpected: %s\nactual:   %s",
			caseDir, path, expected, actual)
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
		t.Fatalf("case %s: generated file missing at %s (expected path declared in %s)",
			caseDir, genPath, pathFile)
	}
	data, err := os.ReadFile(genPath)
	if err != nil {
		t.Fatalf("case %s: read generated file %s: %v", caseDir, genPath, err)
	}
	actualHash := fmt.Sprintf("%x", sha256.Sum256(data))
	if actualHash != expectedHash {
		t.Fatalf("case %s: generated file hash mismatch for %s (expected hash from %s)\nexpected: %s\nactual:   %s",
			caseDir, genPath, hashFile, expectedHash, actualHash)
	}
}

// --- Utilities ---

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// expectsJSONStdout reports whether the fixture ships an
// expected.* file that drives a stdout-JSON validator. The set
// covers every check that calls extractJSONPath / json.Unmarshal
// on captured stdout (checkSummary, checkFindingsCount,
// checkInputHashes, checkSourceEvidence, checkFullOutput,
// checkSARIF). Adding a new JSON-shape expected file later
// requires extending this list; the gate just below uses the
// same predicate.
func expectsJSONStdout(caseDir string) bool {
	return fileExists(filepath.Join(caseDir, "expected.summary.json")) ||
		fileExists(filepath.Join(caseDir, "expected.findings.count")) ||
		fileExists(filepath.Join(caseDir, "expected.input_hashes.json")) ||
		fileExists(filepath.Join(caseDir, "expected.source_evidence.json")) ||
		fileExists(filepath.Join(caseDir, "expected.out.json")) ||
		fileExists(filepath.Join(caseDir, "expected.out.sarif"))
}

// argsContainFormat reports whether the fixture's args.txt
// already supplies a --format / -f flag. Used by the apply-path
// command builder to avoid double-injecting --format json when
// a fixture explicitly chooses a different output shape.
func argsContainFormat(caseDir string) bool {
	argsFile := filepath.Join(caseDir, "args.txt")
	if !fileExists(argsFile) {
		return false
	}
	data, err := os.ReadFile(argsFile)
	if err != nil {
		return false
	}
	for tok := range strings.FieldsSeq(string(data)) {
		if tok == "--format" || tok == "-f" || strings.HasPrefix(tok, "--format=") || strings.HasPrefix(tok, "-f=") {
			return true
		}
	}
	return false
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
