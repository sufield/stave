package verify

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestVerifyOutputByteIdentical(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	projectRoot := filepath.Join(filepath.Dir(filename), "../../..")

	binPath := filepath.Join(t.TempDir(), "stave-test")
	buildCmd := exec.Command("go", "build", "-o", binPath, "./cmd/stave")
	buildCmd.Dir = projectRoot
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build stave: %v\n%s", err, out)
	}

	fixtureDir := filepath.Join(projectRoot, "testdata", "e2e", "e2e-s3-verify")
	beforeDir := filepath.Join(fixtureDir, "before")
	afterDir := filepath.Join(fixtureDir, "after")
	ctlDir := filepath.Join(fixtureDir, "controls")

	args := []string{
		"verify",
		"--before", beforeDir,
		"--after", afterDir,
		"--controls", ctlDir,
		"--now", "2026-01-11T00:00:00Z",
	}

	run := func() []byte {
		cmd := exec.Command(binPath, args...)
		cmd.Dir = projectRoot
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		if err != nil {
			t.Fatalf("verify command failed: %v\nstderr: %s", err, stderr.String())
		}
		return stdout.Bytes()
	}

	run1 := run()
	run2 := run()
	if !bytes.Equal(run1, run2) {
		t.Fatalf("verify output is not byte-identical across runs\nrun1:\n%s\nrun2:\n%s", run1, run2)
	}

	goldenPath := filepath.Join(fixtureDir, "expected.out.json")
	goldenData, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("failed to read golden file: %v", err)
	}

	var golden, actual any
	if err := json.Unmarshal(goldenData, &golden); err != nil {
		t.Fatalf("failed to parse golden JSON: %v", err)
	}
	if err := json.Unmarshal(run1, &actual); err != nil {
		t.Fatalf("failed to parse command output JSON: %v\noutput: %s", err, run1)
	}

	// Tool version varies between test binaries (e.g., "dev" vs release tags).
	// Keep golden comparison semantic by normalizing this field away.
	if gm, ok := golden.(map[string]any); ok {
		if run, ok := gm["run"].(map[string]any); ok {
			delete(run, "tool_version")
		}
	}
	if am, ok := actual.(map[string]any); ok {
		if run, ok := am["run"].(map[string]any); ok {
			delete(run, "tool_version")
		}
	}

	goldenNorm, _ := json.Marshal(golden)
	actualNorm, _ := json.Marshal(actual)
	if !bytes.Equal(goldenNorm, actualNorm) {
		t.Fatalf("verify output does not match golden file\ngot:\n%s\nwant:\n%s", run1, goldenData)
	}
}
