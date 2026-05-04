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
		Code:   ui.CodeInternalError,
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
	a.writeErrorInfo(errorInfoFromError(err, errMsg))
}

func errorInfoFromError(err error, message string) *ui.ErrorInfo {
	hint := ui.SuggestForError(err)
	docsRef := metadata.DocsRef(hint.SearchQuery)
	suggested := ""
	if hint.NextCommand != "" {
		suggested = fmt.Sprintf("Try `%s`. ", hint.NextCommand)
	}

	if ui.IsSentinel(err) {
		exit := ExitCode(err)
		if tmpl, ok := sentinelTemplates[exit]; ok {
			return ui.NewErrorInfo(tmpl.Code, message).
				WithTitle(tmpl.Title).
				WithAction(suggested + tmpl.Action).
				WithURL(docsRef)
		}
		// Sentinel without a template entry means a new sentinel was
		// added but sentinelTemplates wasn't extended — surface the
		// gap via slog so a maintainer notices in -v mode rather than
		// the operator silently getting the generic "Command failed"
		// fallback. The exit code stays correct because ExitCode()
		// classified it; only the user-facing template is missing.
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

// isValidationSentinel returns true for the validation-failed family
// of sentinels. Validation errors stay in IsSentinel so they map to
// the right exit code, but unlike finding sentinels they don't
// always emit user-facing output before returning, so the executor
// must run writeCommandError for them. Carved out as a tiny named
// helper rather than inlining errors.Is twice in handleExecutionError.
func isValidationSentinel(err error) bool {
	return errors.Is(err, ui.ErrValidationWarnings) || errors.Is(err, ui.ErrValidationFailed)
}
