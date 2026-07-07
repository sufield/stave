package validate

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/diagnose"
	"github.com/sufield/stave/internal/cli/ui"
)

// testdataDir returns the path to a testdata e2e fixture directory.
func testdataDir(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(findRepoRoot(t), "testdata", "e2e", name)
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("cannot get working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("cannot find repo root (no go.mod found)")
		}
		dir = parent
	}
}

// TestExitCode tests the ExitCode function with various error conditions.
// Exit code contract: 0=success, 2=input/validation error, 3=violations, 130=interrupted.
func TestExitCode(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected int
	}{
		{"clean validation returns 0", nil, 0},
		{"validation errors returns 2", ui.ErrValidationFailed, 2},
		{"validation warnings returns 2", ui.ErrValidationWarnings, 2},
		{"violations found returns 3", ui.ErrViolationsFound, 3},
		{"unknown error returns 4 (internal)", errors.New("some other error"), 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ui.ExitCode(tt.err); got != tt.expected {
				t.Errorf("ui.ExitCode(%v) = %d, want %d", tt.err, got, tt.expected)
			}
		})
	}
}

func TestRunValidate_DirectoryMode_ValidatesBothArtifacts(t *testing.T) {
	fixture := testdataDir(t, "e2e-01-violation")
	opts := &options{
		Controls:          filepath.Join(fixture, "controls"),
		Observations:      filepath.Join(fixture, "observations"),
		MaxUnsafeDuration: "168h",
		EvalTimeRaw:       "2026-01-15T00:00:00Z",
		Format:            "text",
	}

	var stdout, stderr bytes.Buffer
	err := runValidate(context.Background(), Input{
		Out:    &stdout,
		Stderr: &stderr,
		Format: "text",
		Rt:     ui.DefaultRuntime(),
		Opts:   opts,
	})
	if err != nil {
		t.Fatalf("expected directory validate to pass, got: %v\nstderr: %s", err, stderr.String())
	}
	output := stdout.String()
	if !strings.Contains(output, "Validation passed") {
		t.Fatalf("expected validation success output, got: %s", output)
	}
	if !strings.Contains(output, "Checked: 1 controls, 3 snapshots") {
		t.Fatalf("expected both controls and snapshots to be counted, got: %s", output)
	}
}

// TestValidateHelpText verifies validate command help contains required sections.
func TestValidateHelpText(t *testing.T) {
	help := NewCmd(ui.DefaultRuntime()).Long
	required := []string{"What it checks:", "Control schema", "Observation schema", "Duration format"}
	for _, section := range required {
		if !strings.Contains(help, section) {
			t.Errorf("validate help missing required section: %s", section)
		}
	}
}

// TestDiagnoseHelpText verifies diagnose command help contains required sections.
func TestDiagnoseHelpText(t *testing.T) {
	df := compose.DefaultFactories()
	cmd := diagnose.NewDiagnoseCmd(df.NewObsRepo, df.NewCtlRepo)
	help := cmd.Long
	required := []string{"Inputs:", "Outputs:", "Exit Codes:"}
	for _, section := range required {
		if !strings.Contains(help, section) {
			t.Errorf("diagnose help missing required section: %s", section)
		}
	}
	if !strings.Contains(help, "Examples:") && strings.TrimSpace(cmd.Example) == "" {
		t.Error("diagnose help missing examples (expected in Long or Example field)")
	}
}

// TestQuietModeOutputs tests that quiet mode suppresses text stdout output
// but preserves JSON output for scripting.
func TestQuietModeOutputs(t *testing.T) {
	out := compose.ResolveStdout(nil, true, "text")
	if out != io.Discard {
		t.Error("quiet+text mode should return io.Discard")
	}
	out = compose.ResolveStdout(nil, true, "json")
	if out == io.Discard {
		t.Error("quiet+json mode should preserve stdout (fallback to os.Stdout) for piping")
	}
}

// TestExitCodesContract tests that exit codes match the documented contract.
func TestExitCodesContract(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected int
	}{
		{"success returns 0", nil, 0},
		{"validation failed returns 2", ui.ErrValidationFailed, 2},
		{"validation warnings returns 2", ui.ErrValidationWarnings, 2},
		{"violations found returns 3", ui.ErrViolationsFound, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ui.ExitCode(tt.err); got != tt.expected {
				t.Errorf("ui.ExitCode(%v) = %d, want %d", tt.err, got, tt.expected)
			}
		})
	}
}
