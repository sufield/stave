package securityaudit

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/sufield/stave/internal/cli/ui"
)

// TestSecurityAuditCLIContract validates the security-audit command's public
// CLI contract: flag parsing, JSON output structure, exit code mapping, and
// stdout/stderr stream separation. Follows the pattern established by
// cmd/capabilities_contract_test.go.

func TestSecurityAuditCLIContract_JSONOutput(t *testing.T) {
	cmd := NewCmd()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{
		"--format", "json",
		"--now", "2026-01-15T00:00:00Z",
		"--fail-on", "NONE",
	})

	err := cmd.Execute()
	// --fail-on NONE may still gate if there are real findings; accept
	// either nil or ErrSecurityAuditFindings.
	if err != nil && !errors.Is(err, ui.ErrSecurityAuditFindings) {
		t.Fatalf("unexpected error: %v\nstderr: %s", err, stderr.String())
	}

	var report map[string]any
	if jsonErr := json.Unmarshal(stdout.Bytes(), &report); jsonErr != nil {
		t.Fatalf("stdout is not valid JSON: %v\noutput: %s", jsonErr, stdout.String())
	}

	// Verify required top-level keys.
	for _, key := range []string{"schema_version", "tool_version", "summary", "findings"} {
		if _, ok := report[key]; !ok {
			t.Errorf("missing required top-level key %q in JSON report", key)
		}
	}
}

func TestSecurityAuditCLIContract_ExitCodeGating(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "bundle")

	cmd := NewCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--format", "json",
		"--now", "2026-01-15T00:00:00Z",
		"--fail-on", "HIGH",
		"--out-dir", outDir,
	})

	err := cmd.Execute()
	if !errors.Is(err, ui.ErrSecurityAuditFindings) {
		t.Fatalf("expected ErrSecurityAuditFindings (exit 1), got %v", err)
	}
	if got := ui.ExitCode(err); got != 1 {
		t.Errorf("exit code = %d, want 1", got)
	}
}

func TestSecurityAuditCLIContract_InvalidFormat(t *testing.T) {
	cmd := NewCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--format", "bogus"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
	if got := ui.ExitCode(err); got != 2 {
		t.Errorf("exit code = %d, want 2 (input error)", got)
	}
}

func TestSecurityAuditCLIContract_StreamSeparation(t *testing.T) {
	cmd := NewCmd()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{
		"--format", "json",
		"--now", "2026-01-15T00:00:00Z",
		"--fail-on", "NONE",
	})

	err := cmd.Execute()
	if err != nil && !errors.Is(err, ui.ErrSecurityAuditFindings) {
		t.Fatalf("unexpected error: %v", err)
	}

	// stdout must contain valid JSON (the report).
	if stdout.Len() == 0 {
		t.Fatal("stdout is empty; expected JSON report")
	}
	if !json.Valid(stdout.Bytes()) {
		t.Errorf("stdout is not valid JSON:\n%s", stdout.String())
	}

	// stderr must not contain JSON report data (it may contain diagnostics).
	if stderr.Len() > 0 && json.Valid(stderr.Bytes()) {
		t.Error("stderr contains valid JSON; report may have leaked to stderr")
	}
}
