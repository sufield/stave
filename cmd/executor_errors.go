package cmd

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/metadata"
)

// errorTemplate defines the UI metadata for a sentinel error category.
type errorTemplate struct {
	Code   ui.ErrorCode
	Title  string
	Action string
}

// sentinelTemplates maps exit codes to their error presentation metadata.
// Every exit code that ui.IsSentinel can attach to an error must have an
// entry here, otherwise errorInfoFromError falls through to the generic
// "Command failed" path and the operator sees less specific guidance
// than they could.
var sentinelTemplates = map[int]errorTemplate{
	ui.ExitSecurity: {
		Code:   ui.CodeSecurityAuditFindings,
		Title:  "Security audit gate failed",
		Action: "Review the generated security-audit report and remediate findings at or above --fail-on.",
	},
	ui.ExitViolations: {
		Code:   ui.CodeViolationsFound,
		Title:  "Violations detected",
		Action: "Review findings and re-run `stave diagnose` for root-cause guidance.",
	},
	ui.ExitInputError: {
		Code:   ui.CodeInvalidInput,
		Title:  "Input validation failed",
		Action: "Run `stave validate` with the same inputs to get actionable fix hints.",
	},
	ui.ExitInternal: {
		Code:   ui.CodeInternalError,
		Title:  "Internal error",
		Action: "Rerun with -vv to capture the full trace, then file an issue with the captured output.",
	},
	ui.ExitInterrupted: {
		Code:   ui.CodeInterrupted,
		Title:  "Interrupted",
		Action: "Command was canceled before completion (Ctrl-C / SIGTERM). Re-run when ready; partial outputs may be incomplete.",
	},
}

func (a *App) writeCommandError(err error, args []string) {
	if err == nil {
		return
	}
	errMsg := ensureFirstRunRunHint(err.Error(), args)
	errMsg = a.sanitizeExecuteMessage(errMsg)
	a.writeErrorInfo(a.errorInfoFromError(err, errMsg))
}

func (a *App) errorInfoFromError(err error, message string) *ui.ErrorInfo {
	hint := ui.SuggestForError(err)
	docsRef := metadata.DocsRef(hint.SearchQuery)
	suggested := ""
	if hint.NextCommand != "" {
		// Run the suggested command through the same sanitizer that
		// already cleaned `message`. SuggestForError can echo path
		// fragments and asset IDs from the originating error into
		// its NextCommand template, so without this pass an
		// otherwise-redacted error rendering would leak the same
		// identifier through the "Try `…`" hint line.
		nextCmd := a.sanitizeExecuteMessage(hint.NextCommand)
		suggested = fmt.Sprintf("Try `%s`. ", nextCmd)
	}

	return resolvePrimaryErrorSignal(err, message, suggested, docsRef)
}

// resolvePrimaryErrorSignal applies the documented precedence
// policy that maps an error chain onto the user-facing ui.ErrorInfo:
//
//  1. Sentinel-with-template: if the error is a sentinel
//     (errors.Is unwraps so a UserError wrapping a sentinel still
//     resolves here) AND its exit code has a template entry, use
//     the template. Sentinels carry actionable remediation
//     (workflow-specific exit-code guidance) that beats the
//     generic UserError fallback below.
//  2. Sentinel-without-template: surface the gap via slog so a
//     maintainer notices the missing entry in -v mode, then fall
//     through. Exit code stays correct because ExitCode() already
//     classified it; only the user-facing copy is missing.
//  3. UserError: input validation issue — surface as a
//     CodeInvalidInput with the canonical "check the command
//     arguments" remediation.
//  4. Generic command failure: the catch-all CodeInternalError.
//
// Centralising the policy here means a future change ("UserError
// wrapping should override a generic sentinel") edits one place
// instead of unwinding the original if-cascade.
func resolvePrimaryErrorSignal(err error, message, suggested, docsRef string) *ui.ErrorInfo {
	if ui.IsSentinel(err) {
		exit := ExitCode(err)
		if tmpl, ok := sentinelTemplates[exit]; ok {
			return ui.NewErrorInfo(tmpl.Code, message).
				WithTitle(tmpl.Title).
				WithAction(suggested + tmpl.Action).
				WithURL(docsRef)
		}
		slog.Warn("executor: sentinel error has no template entry; falling back to generic message",
			"exit_code", exit, "error", message)
	}

	var userErr *ui.UserError
	if errors.As(err, &userErr) {
		return ui.NewErrorInfo(ui.CodeInvalidInput, message).
			WithTitle("Input validation failed").
			WithAction(suggested + "Check the command arguments and rerun with -v or -vv for additional context.").
			WithURL(docsRef)
	}

	return ui.NewErrorInfo(ui.CodeInternalError, message).
		WithTitle("Command failed").
		WithAction(suggested + "Check the command arguments and rerun with -v or -vv for additional context.").
		WithURL(docsRef)
}

// writeErrorInfo uses os.Stderr directly because this runs after command
// execution completes — the Cobra command and its writers may no longer be valid.
func (a *App) writeErrorInfo(errInfo *ui.ErrorInfo) {
	if errInfo == nil {
		return
	}
	writeErr := ui.WriteErrorText(os.Stderr, errInfo)
	if writeErr != nil {
		// Last resort: stderr write failed. Try a minimal fallback.
		fmt.Fprintf(os.Stderr, "error: %s (additionally, writing error details failed: %v)\n", errInfo.Message, writeErr)
	}
}

// isSentinelError returns true if the error is a sentinel error that signals
// a specific exit condition rather than a failure message to display.
func isSentinelError(err error) bool {
	return ui.IsSentinel(err)
}
