package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/metadata"
)

func (a *App) writeCommandError(err error, args []string) {
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
	switch {
	case ui.IsSentinel(err) && ExitCode(err) == ui.ExitSecurity:
		return ui.NewErrorInfo(ui.CodeSecurityAuditFindings, message).
			WithTitle("Security audit gate failed").
			WithAction(suggested + "Review the generated security-audit report and remediate findings at or above --fail-on.").
			WithURL(docsRef)
	case ui.IsSentinel(err) && ExitCode(err) == ui.ExitViolations:
		return ui.NewErrorInfo(ui.CodeViolationsFound, message).
			WithTitle("Violations detected").
			WithAction(suggested + "Review findings and re-run `stave diagnose` for root-cause guidance.").
			WithURL(docsRef)
	case ui.IsSentinel(err) && ExitCode(err) == ui.ExitInputError:
		return ui.NewErrorInfo(ui.CodeInvalidInput, message).
			WithTitle("Input validation failed").
			WithAction(suggested + "Run `stave validate` with the same inputs to get actionable fix hints.").
			WithURL(docsRef)
	case errors.As(err, new(*ui.UserError)):
		return ui.NewErrorInfo(ui.CodeInvalidInput, message).
			WithTitle("Input validation failed").
			WithAction(suggested + "Check the command arguments and rerun with -v or -vv for additional context.").
			WithURL(docsRef)
	default:
		return ui.NewErrorInfo(ui.CodeInternalError, message).
			WithTitle("Command failed").
			WithAction(suggested + "Check the command arguments and rerun with -v or -vv for additional context.").
			WithURL(docsRef)
	}
}

// writeErrorInfo uses os.Stderr directly because this runs after command
// execution completes — the Cobra command and its writers may no longer be valid.
func (a *App) writeErrorInfo(errInfo *ui.ErrorInfo) {
	if errInfo == nil {
		return
	}
	if a.isJSONMode() {
		_ = ui.WriteErrorJSON(os.Stderr, errInfo)
	} else {
		_ = ui.WriteErrorText(os.Stderr, errInfo)
	}
}

// isSentinelError returns true if the error is a sentinel error that signals
// a specific exit condition rather than a failure message to display.
func isSentinelError(err error) bool {
	return ui.IsSentinel(err)
}
