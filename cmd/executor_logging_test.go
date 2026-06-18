package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/cli/ui"
)

// captureOutcomeLog runs logExecutionOutcome against a JSON logger and
// returns the single decoded record.
func captureOutcomeLog(t *testing.T, err error, msg string, exitCode int) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	logExecutionOutcome(logger, err, msg, exitCode)
	line := strings.TrimSpace(buf.String())
	if line == "" {
		t.Fatal("logExecutionOutcome produced no log line")
	}
	var rec map[string]any
	if jerr := json.Unmarshal([]byte(line), &rec); jerr != nil {
		t.Fatalf("log line is not valid JSON: %v\n%s", jerr, line)
	}
	return rec
}

// TestLogExecutionOutcome_ViolationsIsNotAFailure is the regression for
// the misleading `msg="command failed" error="violations found"
// exit_code=3` line. Exit 3 means the evaluation ran to completion and
// found violations — the intended success-with-findings outcome — so it
// must NOT be logged as a failure, which confused early adopters.
func TestLogExecutionOutcome_ViolationsIsNotAFailure(t *testing.T) {
	rec := captureOutcomeLog(t, ui.ErrViolationsFound, "violations found", ui.ExitViolations)

	if rec["msg"] == "command failed" {
		t.Fatalf("exit 3 (violations found) must not be logged as 'command failed'; got %q", rec["msg"])
	}
	if rec["level"] != "INFO" {
		t.Errorf("violations-found should log at INFO, got level=%v", rec["level"])
	}
	if rec["msg"] != "command completed with findings" {
		t.Errorf("expected msg=\"command completed with findings\", got %q", rec["msg"])
	}
	if rec["exit_code"].(float64) != float64(ui.ExitViolations) {
		t.Errorf("expected exit_code=3, got %v", rec["exit_code"])
	}
}

// TestLogExecutionOutcome_SecurityGateIsNotAFailure covers the analogous
// exit-1 security-audit gating outcome: the audit completed and is
// reporting findings above the threshold, not faulting.
func TestLogExecutionOutcome_SecurityGateIsNotAFailure(t *testing.T) {
	rec := captureOutcomeLog(t, ui.ErrSecurityAuditFindings, "security audit findings", ui.ExitSecurity)
	if rec["msg"] == "command failed" {
		t.Fatalf("exit 1 (security gate) must not be logged as 'command failed'; got %q", rec["msg"])
	}
	if rec["level"] != "INFO" {
		t.Errorf("security-gate should log at INFO, got level=%v", rec["level"])
	}
}

// TestLogExecutionOutcome_RealFailuresStillWarn ensures genuine faults
// (input error exit 2, internal error exit 4) still log at WARN as
// "command failed" — the fix must not silence real problems.
func TestLogExecutionOutcome_RealFailuresStillWarn(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      error
		msg      string
		exitCode int
	}{
		{"internal", ui.ErrInternal, "internal error", ui.ExitInternal},
		{"input", ui.ErrValidationFailed, "validation failed", ui.ExitInputError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := captureOutcomeLog(t, tc.err, tc.msg, tc.exitCode)
			if rec["msg"] != "command failed" {
				t.Errorf("%s (exit %d) should log 'command failed', got %q", tc.name, tc.exitCode, rec["msg"])
			}
			if rec["level"] != "WARN" {
				t.Errorf("%s should log at WARN, got level=%v", tc.name, rec["level"])
			}
		})
	}
}

// TestLogExecutionOutcome_InterruptsStayInfo preserves the existing
// interrupt classification (Ctrl-C / parent timeout are routine, not
// failures).
func TestLogExecutionOutcome_InterruptsStayInfo(t *testing.T) {
	rec := captureOutcomeLog(t, context.Canceled, "context canceled", ui.ExitInterrupted)
	if rec["level"] != "INFO" {
		t.Errorf("context-cancel should log at INFO, got level=%v", rec["level"])
	}
	if rec["msg"] == "command failed" {
		t.Errorf("interrupts must not be logged as 'command failed'")
	}
}
