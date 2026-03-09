package validate

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/diagnose"
	appservice "github.com/sufield/stave/internal/app/service"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/diag"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/testutil"
)

// testdataDir returns the path to a testdata e2e fixture directory.
func testdataDir(t *testing.T, name string) string {
	t.Helper()
	return testutil.E2EDir(t, name)
}

// TestExitCode tests the ExitCode function with various error conditions.
// Exit code contract:
//
//	0 = success
//	2 = input/validation error
//	3 = violations/diagnostics found
//	130 = interrupted
func TestExitCode(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected int
	}{
		{
			name:     "clean validation returns 0",
			err:      nil,
			expected: 0,
		},
		{
			name:     "validation errors returns 2",
			err:      ui.ErrValidationFailed,
			expected: 2,
		},
		{
			name:     "validation warnings returns 2",
			err:      ui.ErrValidationWarnings,
			expected: 2,
		},
		{
			name:     "violations found returns 3",
			err:      ui.ErrViolationsFound,
			expected: 3,
		},
		{
			name:     "unknown error returns 2 (input error)",
			err:      errors.New("some other error"),
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ui.ExitCode(tt.err)
			if got != tt.expected {
				t.Errorf("ui.ExitCode(%v) = %d, want %d", tt.err, got, tt.expected)
			}
		})
	}
}

func TestRunValidate_DirectoryMode_ValidatesBothArtifacts(t *testing.T) {
	fixture := testdataDir(t, "e2e-01-violation")
	opts := &options{
		ControlsDir:     filepath.Join(fixture, "controls"),
		ObservationsDir: filepath.Join(fixture, "observations"),
		MaxUnsafe:       "168h",
		NowTime:         "2026-01-15T00:00:00Z",
		Format:          "text",
	}

	cmd := &cobra.Command{Use: "test"}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	// Exercise full validate command flow (directory mode).
	err := runValidateWithOptions(cmd, ui.NewRuntime(nil, nil), opts)
	if err != nil {
		t.Fatalf("expected directory validate to pass, got: %v", err)
	}
	output := buf.String()

	if !strings.Contains(output, "Validation passed") {
		t.Fatalf("expected validation success output, got: %s", output)
	}
	if !strings.Contains(output, "Checked: 1 controls, 3 snapshots") {
		t.Fatalf("expected both controls and snapshots to be counted, got: %s", output)
	}
}

// TestOutputAndExit_Clean tests outputAndExit with a clean validation result (no errors or warnings).
func TestOutputAndExit_Clean(t *testing.T) {
	// No errors, no warnings → exit 0
	result := &appservice.ValidationResult{
		Diagnostics: &diag.Result{Issues: []diag.Issue{}},
		Summary: appservice.ValidationSummary{
			ControlsLoaded:          2,
			SnapshotsLoaded:         3,
			AssetObservationsLoaded: 10,
		},
	}

	var buf bytes.Buffer
	err := outputAndExitWithOptions(&cobra.Command{Use: "test"}, &buf, result, false, defaultOptions())

	if err != nil {
		t.Errorf("expected nil error for clean validation, got %v", err)
	}
	if ui.ExitCode(err) != 0 {
		t.Errorf("expected exit code 0, got %d", ui.ExitCode(err))
	}
}

// TestOutputAndExit_Errors tests outputAndExit with validation errors (should return exit code 2).
func TestOutputAndExit_Errors(t *testing.T) {
	// Has errors → exit 2
	result := &appservice.ValidationResult{
		Diagnostics: &diag.Result{Issues: []diag.Issue{
			{
				Code:   diag.CodeControlMissingID,
				Signal: diag.SignalError,
				Action: "Add id field",
			},
		}},
		Summary: appservice.ValidationSummary{
			ControlsLoaded: 1,
		},
	}

	var buf bytes.Buffer
	err := outputAndExitWithOptions(&cobra.Command{Use: "test"}, &buf, result, false, defaultOptions())

	if err == nil {
		t.Error("expected error for validation with errors")
	}
	if ui.ExitCode(err) != 2 {
		t.Errorf("expected exit code 2, got %d", ui.ExitCode(err))
	}
}

// TestOutputAndExit_WarningsOnly tests outputAndExit with only warnings (should return exit code 2).
func TestOutputAndExit_WarningsOnly(t *testing.T) {
	// Warnings only, no errors → exit 2
	result := &appservice.ValidationResult{
		Diagnostics: &diag.Result{Issues: []diag.Issue{
			{
				Code:   diag.CodeSingleSnapshot,
				Signal: diag.SignalWarn,
				Action: "Add more snapshots",
			},
			{
				Code:   diag.CodeSpanLessThanMaxUnsafe,
				Signal: diag.SignalWarn,
				Action: "Reduce max-unsafe",
			},
		}},
		Summary: appservice.ValidationSummary{
			SnapshotsLoaded: 1,
		},
	}

	var buf bytes.Buffer
	err := outputAndExitWithOptions(&cobra.Command{Use: "test"}, &buf, result, false, defaultOptions())

	if err == nil {
		t.Error("expected error for validation with warnings")
	}
	if ui.ExitCode(err) != 2 {
		t.Errorf("expected exit code 2, got %d", ui.ExitCode(err))
	}
}

// TestOutputAndExit_ErrorsAndWarnings tests outputAndExit with both errors and warnings (errors take precedence, exit code 2).
func TestOutputAndExit_ErrorsAndWarnings(t *testing.T) {
	// Has both errors and warnings → exit 2 (errors take precedence)
	result := &appservice.ValidationResult{
		Diagnostics: &diag.Result{Issues: []diag.Issue{
			{
				Code:   diag.CodeControlMissingID,
				Signal: diag.SignalError,
				Action: "Add id field",
			},
			{
				Code:   diag.CodeSingleSnapshot,
				Signal: diag.SignalWarn,
				Action: "Add more snapshots",
			},
		}},
		Summary: appservice.ValidationSummary{
			ControlsLoaded:  1,
			SnapshotsLoaded: 1,
		},
	}

	var buf bytes.Buffer
	err := outputAndExitWithOptions(&cobra.Command{Use: "test"}, &buf, result, false, defaultOptions())

	if err == nil {
		t.Error("expected error for validation with errors")
	}
	if ui.ExitCode(err) != 2 {
		t.Errorf("expected exit code 2, got %d", ui.ExitCode(err))
	}
}

// TestOutputAndExit_JSONOutput tests outputAndExit with JSON output format.
func TestOutputAndExit_JSONOutput(t *testing.T) {
	opts := defaultOptions()
	opts.FixHints = false
	result := &appservice.ValidationResult{
		Diagnostics: &diag.Result{Issues: []diag.Issue{
			{
				Code:   diag.CodeSingleSnapshot,
				Signal: diag.SignalWarn,
				Evidence: kernel.NewSanitizableMap(map[string]string{
					"snapshot_count": "1",
				}),
				Action: "Add more snapshots",
			},
		}},
		Summary: appservice.ValidationSummary{
			SnapshotsLoaded: 1,
		},
	}

	var buf bytes.Buffer
	err := outputAndExitWithOptions(&cobra.Command{Use: "test"}, &buf, result, true, opts)

	// Check JSON output contains expected fields
	output := buf.String()
	if !strings.Contains(output, `"schema_version": "validate.v0.1"`) {
		t.Errorf("expected JSON to contain schema_version, got %s", output)
	}
	if !strings.Contains(output, `"valid": true`) {
		t.Errorf("expected JSON to contain 'valid': true, got %s", output)
	}
	if !strings.Contains(output, `"code": "SINGLE_SNAPSHOT"`) {
		t.Errorf("expected JSON to contain warning code, got %s", output)
	}

	// Should return warnings error
	if ui.ExitCode(err) != 2 {
		t.Errorf("expected exit code 2 for warnings, got %d", ui.ExitCode(err))
	}
}

func TestWriteValidationText_WithFixHints(t *testing.T) {
	opts := defaultOptions()
	opts.FixHints = true
	opts.ControlsDir = "./controls"
	opts.ObservationsDir = "./observations"

	result := &appservice.ValidationResult{
		Diagnostics: &diag.Result{Issues: []diag.Issue{
			{
				Code:   diag.CodeObservationLoadFailed,
				Signal: diag.SignalError,
				Action: "Check observations",
				Evidence: kernel.NewSanitizableMap(map[string]string{
					"directory": "./observations",
				}),
			},
		}},
	}

	var buf bytes.Buffer
	if err := writeValidationTextWithOptions(&buf, result, opts); err != nil {
		t.Fatalf("writeValidationText failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Suggested next commands:") {
		t.Fatalf("expected fix hints section, got: %s", out)
	}
	if !strings.Contains(out, "stave ingest --profile aws-s3") {
		t.Fatalf("expected ingest hint, got: %s", out)
	}
}

func TestOutputAndExit_JSONOutput_WithFixHints(t *testing.T) {
	opts := defaultOptions()
	opts.FixHints = true

	result := &appservice.ValidationResult{
		Diagnostics: &diag.Result{Issues: []diag.Issue{
			{
				Code:    "INVALID_MAX_UNSAFE",
				Signal:  diag.SignalError,
				Action:  "Use valid duration",
				Command: "stave validate --max-unsafe 168h",
			},
		}},
	}

	var buf bytes.Buffer
	_ = outputAndExitWithOptions(&cobra.Command{Use: "test"}, &buf, result, true, opts)
	out := buf.String()
	if !strings.Contains(out, `"fix_hints"`) {
		t.Fatalf("expected fix_hints in json output, got: %s", out)
	}
	if !strings.Contains(out, "stave validate --max-unsafe 168h") {
		t.Fatalf("expected command hint in json output, got: %s", out)
	}
}

// TestValidateHelpText verifies validate command help contains required sections.
func TestValidateHelpText(t *testing.T) {
	help := NewCmd(nil).Long
	required := []string{"Purpose:", "Inputs:", "Outputs:", "Exit Codes:", "Examples:"}
	for _, section := range required {
		if !strings.Contains(help, section) {
			t.Errorf("validate help missing required section: %s", section)
		}
	}
}

// TestDiagnoseHelpText verifies diagnose command help contains required sections.
func TestDiagnoseHelpText(t *testing.T) {
	help := diagnose.NewDiagnoseCmd().Long
	required := []string{"Purpose:", "Inputs:", "Outputs:", "Exit Codes:", "Examples:"}
	for _, section := range required {
		if !strings.Contains(help, section) {
			t.Errorf("diagnose help missing required section: %s", section)
		}
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
		t.Error("quiet+json mode should preserve stdout for piping")
	}
}

// TestExitCodesContract tests that exit codes match the documented contract.
func TestExitCodesContract(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected int
	}{
		// Exit code 0: Success
		{"success returns 0", nil, 0},
		// Exit code 2: Input/validation errors
		{"validation failed returns 2", ui.ErrValidationFailed, 2},
		{"validation warnings returns 2", ui.ErrValidationWarnings, 2},
		// Exit code 3: Violations/diagnostics found
		{"violations found returns 3", ui.ErrViolationsFound, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ui.ExitCode(tt.err)
			if got != tt.expected {
				t.Errorf("ui.ExitCode(%v) = %d, want %d (contract: 0=success, 2=input error, 3=violations)", tt.err, got, tt.expected)
			}
		})
	}
}
