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

// ErrorInfo contains structured error details.
type ErrorInfo struct {
	Code     string            `json:"code"`
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
	CodeIOError         = "IO_ERROR"
	CodeParseError      = "PARSE_ERROR"
	CodeSchemaError     = "SCHEMA_ERROR"
	CodeInternalError   = "INTERNAL_ERROR"
	CodeInvalidInput    = "INVALID_INPUT"
	CodeMissingRequired = "MISSING_REQUIRED"
	CodeViolationsFound = "VIOLATIONS_FOUND"
	CodeDiagnostics     = "DIAGNOSTICS_FOUND"
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
//   - 2: Invalid input, schema validation failure
//   - 3: Violations found (evaluate) or diagnostics found (diagnose)
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
		// Unrecognized errors are unexpected → exit 4 (internal error).
		return ExitInternal
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
func NewErrorInfo(code, message string) *ErrorInfo {
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

// SafetyExitError maps a safety status string to the appropriate sentinel error.
// Returns nil for "SAFE", ErrViolationsFound for "UNSAFE" or "BORDERLINE".
// The status values correspond to evaluation.SafetyStatus constants.
func SafetyExitError(status string) error {
	switch status {
	case "UNSAFE", "BORDERLINE":
		return ErrViolationsFound
	default:
		return nil
	}
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
