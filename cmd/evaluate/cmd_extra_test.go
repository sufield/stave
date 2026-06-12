package evaluate

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ui "github.com/sufield/stave/internal/cli/ui"
)

// The schema/bucket/account/registry helper tests moved to pkg/stave with
// the EvaluateSnapshot facade; this file keeps the command-side tests
// (ExitCode classification, resolveOutput file handling, and the
// missing-stave.yaml integration guard).

func TestExitCode_Nil(t *testing.T) {
	if ExitCode(nil) != 0 {
		t.Fatal("expected 0 for nil error")
	}
}

func TestExitCode_SecurityAuditFindings(t *testing.T) {
	err := fmt.Errorf("%w: 2 CRITICAL", ui.ErrSecurityAuditFindings)
	if ExitCode(err) != 1 {
		t.Fatalf("expected 1, got %d", ExitCode(err))
	}
}

func TestExitCode_OtherError(t *testing.T) {
	// Unclassified errors map to ExitInternal (4) in the global classifier.
	err := io.EOF
	if got := ExitCode(err); got != 4 {
		t.Fatalf("expected 4, got %d", got)
	}
}

func TestResolveOutput_Stdout(t *testing.T) {
	var buf bytes.Buffer
	w, closer, err := resolveOutput("", &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var nilErr error
	closer(&nilErr)
	if w != &buf {
		t.Fatal("expected stdout writer")
	}
}

func TestResolveOutput_File(t *testing.T) {
	tmp := t.TempDir()
	path := tmp + "/output.json"
	w, closer, err := resolveOutput(path, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var nilErr error
	defer closer(&nilErr)
	if w == nil {
		t.Fatal("expected non-nil writer")
	}
}

// TestEvaluate_NoStaveYAML confirms a missing stave.yaml is not a fatal
// error: evaluate must succeed with an empty exceptions list.
func TestEvaluate_NoStaveYAML(t *testing.T) {
	origCwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	snap := filepath.Join(origCwd, "testdata", "snapshots", "hipaa_fixture.json")

	// Switch to a tempdir with no stave.yaml so the "stave.yaml" lookup
	// resolves to an absent file.
	t.Chdir(t.TempDir())

	cmd := NewCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{
		"--snapshot", snap,
		"--profile", "hipaa",
		"--format", "json",
	})

	execErr := cmd.Execute()
	// HIPAA fixture intentionally fails its checks, so the command returns
	// an exit-1 error. Guard only against the load-exceptions failure mode.
	if execErr != nil && strings.Contains(execErr.Error(), "load exceptions") {
		t.Fatalf("evaluate must not fail on missing stave.yaml: %v", execErr)
	}
}
