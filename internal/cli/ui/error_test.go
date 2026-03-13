package ui

import (
	"bytes"
	"encoding/json"
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
			name:     "unrecognized errors return 2 (input error)",
			err:      errors.New("some error"),
			expected: ExitInputError,
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

func TestWriteErrorJSON(t *testing.T) {
	var buf bytes.Buffer
	info := NewErrorInfo(CodeIOError, "file not found").
		WithAction("check the file path").
		WithEvidence("path", "/some/path")

	err := WriteErrorJSON(&buf, info)
	if err != nil {
		t.Fatalf("WriteErrorJSON failed: %v", err)
	}

	// Parse the output
	var result ErrorEnvelope
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	if result.OK {
		t.Error("expected ok=false in error envelope")
	}
	if result.Error == nil {
		t.Fatal("expected error in envelope")
	}
	if result.Error.Code != CodeIOError {
		t.Errorf("expected code=%s, got %s", CodeIOError, result.Error.Code)
	}
	if result.Error.Message != "file not found" {
		t.Errorf("expected message='file not found', got %s", result.Error.Message)
	}
	if result.Error.Action != "check the file path" {
		t.Errorf("expected action='check the file path', got %s", result.Error.Action)
	}
	if result.Error.Evidence["path"] != "/some/path" {
		t.Errorf("expected evidence.path='/some/path', got %s", result.Error.Evidence["path"])
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
		WithURL("https://example.com/docs").
		WithEvidence("field", "name").
		WithEvidence("reason", "missing")

	if info.Title != "Schema mismatch" {
		t.Errorf("expected title='Schema mismatch', got %s", info.Title)
	}
	if info.Action != "fix the schema" {
		t.Errorf("expected action='fix the schema', got %s", info.Action)
	}
	if info.URL != "https://example.com/docs" {
		t.Errorf("expected url='https://example.com/docs', got %s", info.URL)
	}
	if len(info.Evidence) != 2 {
		t.Errorf("expected 2 evidence entries, got %d", len(info.Evidence))
	}
	if info.Evidence["field"] != "name" {
		t.Errorf("expected evidence.field='name', got %s", info.Evidence["field"])
	}
	if info.Evidence["reason"] != "missing" {
		t.Errorf("expected evidence.reason='missing', got %s", info.Evidence["reason"])
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
