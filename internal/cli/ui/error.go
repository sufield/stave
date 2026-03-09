// Error envelope format and exit code mapping.
package ui

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// ErrorEnvelope is the standard JSON error format for all commands.
type ErrorEnvelope struct {
	OK    bool       `json:"ok"`
	Error *ErrorInfo `json:"error,omitempty"`
}

// ErrorCode is a typed error code for structured CLI error envelopes.
type ErrorCode string

// ErrorInfo contains structured error details.
type ErrorInfo struct {
	Code     ErrorCode         `json:"code"`
	Title    string            `json:"title,omitempty"`
	Message  string            `json:"message"`
	Action   string            `json:"action,omitempty"`
	URL      string            `json:"url,omitempty"`
	Evidence map[string]string `json:"evidence,omitempty"`
}

// Error returns a concise string representation for ErrorInfo.
func (e *ErrorInfo) Error() string {
	if e == nil {
		return ""
	}
	if e.Title != "" {
		return fmt.Sprintf("[%s] %s: %s", e.Code, e.Title, e.Message)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// Common error codes.
const (
	CodeIOError               ErrorCode = "IO_ERROR"
	CodeParseError            ErrorCode = "PARSE_ERROR"
	CodeSchemaError           ErrorCode = "SCHEMA_ERROR"
	CodeInternalError         ErrorCode = "INTERNAL_ERROR"
	CodeInvalidInput          ErrorCode = "INVALID_INPUT"
	CodeMissingRequired       ErrorCode = "MISSING_REQUIRED"
	CodeViolationsFound       ErrorCode = "VIOLATIONS_FOUND"
	CodeDiagnostics           ErrorCode = "DIAGNOSTICS_FOUND"
	CodeSecurityAuditFindings ErrorCode = "SECURITY_AUDIT_FINDINGS"
)

// Exit codes following the contract.
// These are stable for CI/CD integration.
const (
	ExitSuccess     = 0   // No issues, clean run
	ExitSecurity    = 1   // Security-audit gating failure
	ExitInputError  = 2   // Invalid input, schema validation failure
	ExitViolations  = 3   // Evaluation completed with violations found
	ExitInternal    = 4   // Unexpected internal error
	ExitInterrupted = 130 // Interrupted by SIGINT
)

// InputError wraps an error that should exit with ExitInputError (2).
// Unlike sentinel errors, InputError is not suppressed by writeCommandError,
// so the error message (including flag suggestions) is still printed.
type InputError struct{ Err error }

func (e *InputError) Error() string { return e.Err.Error() }
func (e *InputError) Unwrap() error { return e.Err }

// Sentinel errors for exit code mapping.
var (
	ErrViolationsFound       = errors.New("violations found")
	ErrValidationWarnings    = errors.New("validation warnings")
	ErrValidationFailed      = errors.New("validation failed")
	ErrDiagnosticsFound      = errors.New("diagnostics found")
	ErrSecurityAuditFindings = errors.New("security audit findings")
	ErrInterrupted           = errors.New("interrupted")
	ErrInternal              = errors.New("internal error")
)

// ExitCode returns the appropriate exit code for an error.
// Exit code contract:
//   - 0: Success, no issues
//   - 1: Security-audit gating failure
//   - 2: Invalid input, schema validation failure
//   - 3: Violations found (apply) or diagnostics found (diagnose)
//   - 4: Unexpected internal error
//   - 130: Interrupted by SIGINT
func ExitCode(err error) int {
	if err == nil {
		return ExitSuccess
	}

	switch {
	case errors.Is(err, ErrInterrupted):
		return ExitInterrupted
	case errors.Is(err, ErrViolationsFound), errors.Is(err, ErrDiagnosticsFound):
		return ExitViolations
	case errors.Is(err, ErrValidationWarnings), errors.Is(err, ErrValidationFailed):
		return ExitInputError
	case errors.Is(err, ErrSecurityAuditFindings):
		return ExitSecurity
	case errors.Is(err, ErrInternal):
		return ExitInternal
	default:
		var inputErr *InputError
		if errors.As(err, &inputErr) {
			return ExitInputError
		}
		// Unrecognized errors default to exit 2 (input error).
		// True internal errors are caught by the panic handler or ErrInternal.
		return ExitInputError
	}
}

// WriteErrorJSON writes an error envelope to the writer.
func WriteErrorJSON(w io.Writer, info *ErrorInfo) error {
	envelope := ErrorEnvelope{
		OK:    false,
		Error: info,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(envelope)
}

// NewErrorInfo creates an ErrorInfo with the given code and message.
func NewErrorInfo(code ErrorCode, message string) *ErrorInfo {
	return &ErrorInfo{
		Code:    code,
		Message: message,
	}
}

// WithTitle adds a short error title.
func (e *ErrorInfo) WithTitle(title string) *ErrorInfo {
	e.Title = title
	return e
}

// WithAction adds an action suggestion to the error.
func (e *ErrorInfo) WithAction(action string) *ErrorInfo {
	e.Action = action
	return e
}

// WithURL adds a URL with more information.
func (e *ErrorInfo) WithURL(url string) *ErrorInfo {
	e.URL = url
	return e
}

// WithEvidence adds evidence to the error.
func (e *ErrorInfo) WithEvidence(key, value string) *ErrorInfo {
	if e.Evidence == nil {
		e.Evidence = make(map[string]string)
	}
	e.Evidence[key] = value
	return e
}

// IsInputError returns true if the error wraps an InputError.
func IsInputError(err error) bool {
	var inputErr *InputError
	return errors.As(err, &inputErr)
}

// IsSentinel returns true if the error has explicit exit-code mapping.
// These errors produce specific exit codes rather than the default exit 2.
func IsSentinel(err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, ErrViolationsFound),
		errors.Is(err, ErrValidationWarnings),
		errors.Is(err, ErrValidationFailed),
		errors.Is(err, ErrSecurityAuditFindings),
		errors.Is(err, ErrDiagnosticsFound),
		errors.Is(err, ErrInterrupted),
		errors.Is(err, ErrInternal):
		return true
	default:
		return false
	}
}

// WriteErrorText writes a standardized human-readable error structure.
func WriteErrorText(w io.Writer, info *ErrorInfo) error {
	if info == nil {
		return nil
	}
	title := info.Title
	if title == "" {
		title = "Command failed"
	}
	header := SeverityLabel("error", fmt.Sprintf("%s (%s)", title, info.Code), w)

	var out strings.Builder
	out.WriteString(header)
	out.WriteByte('\n')

	if info.Message != "" {
		_, _ = fmt.Fprintf(&out, "Description: %s\n", info.Message)
	}
	if info.Action != "" {
		_, _ = fmt.Fprintf(&out, "Fix: %s\n", info.Action)
	}
	if info.URL != "" {
		_, _ = fmt.Fprintf(&out, "More info: %s\n", info.URL)
	}
	_, err := io.WriteString(w, out.String())
	return err
}
