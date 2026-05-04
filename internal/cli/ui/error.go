// Package ui provides error envelope format, exit code mapping, and user-facing output helpers.
package ui

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
)

// Exit codes following the platform contract.
const (
	ExitSuccess     = 0   // No issues
	ExitSecurity    = 1   // Security-audit gating failure
	ExitInputError  = 2   // Invalid input, flags, or schema validation failure
	ExitViolations  = 3   // Evaluation completed with findings/diagnostics
	ExitInternal    = 4   // Unexpected internal error
	ExitInterrupted = 130 // Interrupted by SIGINT (Ctrl+C)
)

// ErrorCode is a stable string identifier for categories of failures.
type ErrorCode string

// CodeIOError and related constants.
const (
	// CodeIOError constants.
	CodeIOError               ErrorCode = "IO_ERROR"
	CodeParseError            ErrorCode = "PARSE_ERROR"
	CodeSchemaError           ErrorCode = "SCHEMA_ERROR"
	CodeInternalError         ErrorCode = "INTERNAL_ERROR"
	CodeInvalidInput          ErrorCode = "INVALID_INPUT"
	CodeMissingRequired       ErrorCode = "MISSING_REQUIRED"
	CodeViolationsFound       ErrorCode = "VIOLATIONS_FOUND"
	CodeDiagnostics           ErrorCode = "DIAGNOSTICS_FOUND"
	CodeSecurityAuditFindings ErrorCode = "SECURITY_AUDIT_FINDINGS"
	// CodeInterrupted is the telemetry code for an operator-initiated
	// or context-cancelled interrupt. Distinct from CodeInternalError
	// so dashboards can separate "user pressed Ctrl-C" from "engine
	// crashed mid-run" — the previous shape collapsed both into
	// INTERNAL_ERROR, inflating the apparent crash rate.
	CodeInterrupted ErrorCode = "INTERRUPTED"
)

// Sentinel errors used for logic-based exit code mapping. The
// validation-related sentinels are aliased from app/contracts so
// the validation package can return them from Report.ExitError
// without importing cli/ui (a hex-arch violation); errors.Is checks
// against either name continue to work.
var (
	ErrViolationsFound       = appcontracts.ErrViolationsFound
	ErrValidationWarnings    = appcontracts.ErrValidationWarnings
	ErrValidationFailed      = appcontracts.ErrValidationFailed
	ErrDiagnosticsFound      = errors.New("diagnostics found")
	ErrSecurityAuditFindings = errors.New("security audit findings")
	ErrInterrupted           = errors.New("interrupted")
	ErrInternal              = errors.New("internal error")
)

// ErrorInfo contains human-readable and machine-readable error details.
type ErrorInfo struct { //nolint:errname // ErrorXxx is intentional — this is error metadata, not an XxxError
	Code     ErrorCode         `json:"code"`
	Title    string            `json:"title,omitempty"`
	Message  string            `json:"message"`
	Action   string            `json:"action,omitempty"`
	URL      string            `json:"url,omitempty"`
	Evidence map[string]string `json:"evidence,omitempty"`
}

// Error implements the standard error interface.
func (e *ErrorInfo) Error() string {
	if e == nil {
		return ""
	}
	if e.Title != "" {
		return fmt.Sprintf("[%s] %s: %s", e.Code, e.Title, e.Message)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// UserError wraps an error caused by user input that should exit with code 2.
type UserError struct{ Err error }

func (e *UserError) Error() string { return e.Err.Error() }
func (e *UserError) Unwrap() error { return e.Err }

// ExitCode derives the standard exit code from an error chain.
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
	}

	var uErr *UserError
	if errors.As(err, &uErr) {
		return ExitInputError
	}

	// Unknown errors are internal failures — if we can't classify it,
	// it's not a user input problem.
	return ExitInternal
}

// NewErrorInfo creates an ErrorInfo with the given code and message.
func NewErrorInfo(code ErrorCode, message string) *ErrorInfo {
	return &ErrorInfo{
		Code:    code,
		Message: message,
	}
}

// --- Builder Methods ---

// WithTitle adds a short error title.
func (e *ErrorInfo) WithTitle(t string) *ErrorInfo {
	if e != nil {
		e.Title = t
	}
	return e
}

// WithAction adds an action suggestion to the error.
func (e *ErrorInfo) WithAction(a string) *ErrorInfo {
	if e != nil {
		e.Action = a
	}
	return e
}

// WithURL adds a URL with more information.
func (e *ErrorInfo) WithURL(u string) *ErrorInfo {
	if e != nil {
		e.URL = u
	}
	return e
}

// --- Rendering Logic ---

// WriteErrorText prints a formatted, human-readable block describing the error.
func WriteErrorText(w io.Writer, info *ErrorInfo) error {
	if info == nil {
		return nil
	}

	title := info.Title
	if title == "" {
		title = "Execution failed"
	}

	header := SeverityLabel("error", fmt.Sprintf("%s (%s)", title, info.Code), w)

	var sb strings.Builder
	sb.WriteString(header)
	sb.WriteByte('\n')

	if info.Message != "" {
		fmt.Fprintf(&sb, "  Message: %s\n", info.Message)
	}
	if info.Action != "" {
		fmt.Fprintf(&sb, "  Fix:     %s\n", info.Action)
	}
	if info.URL != "" {
		fmt.Fprintf(&sb, "  Help:    %s\n", info.URL)
	}

	if len(info.Evidence) > 0 {
		sb.WriteString("  Evidence:\n")
		// Iterate in sorted key order so identical evidence sets
		// render in identical order across runs. Map iteration is
		// randomised in Go, so the previous shape produced
		// flapping diagnostic output that broke goldens and made
		// support transcripts hard to compare.
		keys := make([]string, 0, len(info.Evidence))
		for k := range info.Evidence {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&sb, "    - %s: %s\n", k, info.Evidence[k])
		}
	}

	_, err := io.WriteString(w, sb.String())
	return err
}

// IsSentinel returns true if the error matches a defined platform sentinel.
func IsSentinel(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrViolationsFound) ||
		errors.Is(err, ErrDiagnosticsFound) ||
		errors.Is(err, ErrValidationWarnings) ||
		errors.Is(err, ErrValidationFailed) ||
		errors.Is(err, ErrSecurityAuditFindings) ||
		errors.Is(err, ErrInterrupted) ||
		errors.Is(err, ErrInternal)
}
