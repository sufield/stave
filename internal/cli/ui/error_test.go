package ui

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestExitCode(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected int
	}{
		{
			name:     "nil returns success (0)",
			err:      nil,
			expected: ExitSuccess,
		},
		{
			name:     "violations found returns 3",
			err:      ErrViolationsFound,
			expected: ExitViolations,
		},
		{
			name:     "diagnostics found returns 3",
			err:      ErrDiagnosticsFound,
			expected: ExitViolations,
		},
		{
			name:     "validation warnings returns 2",
			err:      ErrValidationWarnings,
			expected: ExitInputError,
		},
		{
			name:     "validation failed returns 2",
			err:      ErrValidationFailed,
			expected: ExitInputError,
		},
		{
			name:     "security audit findings returns 1",
			err:      ErrSecurityAuditFindings,
			expected: ExitSecurity,
		},
		{
			name:     "interrupted returns 130",
			err:      ErrInterrupted,
			expected: ExitInterrupted,
		},
		{
			name:     "unrecognized errors return 4 (internal)",
			err:      errors.New("some error"),
			expected: ExitInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExitCode(tt.err)
			if got != tt.expected {
				t.Errorf("ExitCode(%v) = %d, want %d", tt.err, got, tt.expected)
			}
		})
	}
}

func TestIsSentinel(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"violations found", ErrViolationsFound, true},
		{"validation warnings", ErrValidationWarnings, true},
		{"validation failed", ErrValidationFailed, true},
		{"security audit findings", ErrSecurityAuditFindings, true},
		{"diagnostics found", ErrDiagnosticsFound, true},
		{"interrupted", ErrInterrupted, true},
		{"internal error", ErrInternal, true},
		{"other error", errors.New("other"), false},
		{"nil", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsSentinel(tt.err)
			if got != tt.expected {
				t.Errorf("IsSentinel(%v) = %v, want %v", tt.err, got, tt.expected)
			}
		})
	}
}

func TestNewErrorInfo(t *testing.T) {
	info := NewErrorInfo(CodeParseError, "parse failed")
	if info.Code != CodeParseError {
		t.Errorf("expected code=%s, got %s", CodeParseError, info.Code)
	}
	if info.Message != "parse failed" {
		t.Errorf("expected message='parse failed', got %s", info.Message)
	}
}

func TestErrorInfo_Chaining(t *testing.T) {
	info := NewErrorInfo(CodeSchemaError, "invalid schema").
		WithTitle("Schema mismatch").
		WithAction("fix the schema").
		WithURL("https://example.com/docs")

	if info.Title != "Schema mismatch" {
		t.Errorf("expected title='Schema mismatch', got %s", info.Title)
	}
	if info.Action != "fix the schema" {
		t.Errorf("expected action='fix the schema', got %s", info.Action)
	}
	if info.URL != "https://example.com/docs" {
		t.Errorf("expected url='https://example.com/docs', got %s", info.URL)
	}
}

func TestWriteErrorText(t *testing.T) {
	var buf bytes.Buffer
	info := NewErrorInfo(CodeInvalidInput, "invalid --max-unsafe value").
		WithTitle("Input validation failed").
		WithAction("Use values like 168h, 7d, or 1d12h.").
		WithURL("https://github.com/sufield/stave/blob/main/docs/user-docs.md")

	if err := WriteErrorText(&buf, info); err != nil {
		t.Fatalf("WriteErrorText failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "[ERR] Input validation failed (INVALID_INPUT)") {
		t.Fatalf("unexpected output: %s", out)
	}
	if !strings.Contains(out, "  Message: invalid --max-unsafe value") {
		t.Fatalf("missing message: %s", out)
	}
	if !strings.Contains(out, "  Fix:     Use values like 168h, 7d, or 1d12h.") {
		t.Fatalf("missing fix: %s", out)
	}
	if !strings.Contains(out, "  Help:    https://github.com/sufield/stave/blob/main/docs/user-docs.md") {
		t.Fatalf("missing url: %s", out)
	}
}
