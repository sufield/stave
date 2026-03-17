package cmd

import (
	"fmt"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/metadata"
)

func (a *App) recoverExecutePanic() {
	if recovered := recover(); recovered != nil {
		panicMsg := panicMessageFromValue(recovered)
		sanitized := a.sanitizeExecuteMessage(panicMsg)
		userMsg := a.panicUserMessage(sanitized)

		action := "Rerun with -vv, then run `stave-dev doctor` or contact support if this error persists."
		if a.Edition == EditionDev {
			action = "Rerun with -vv, then run `stave bug-report` and attach the bundle if it persists."
		}
		errInfo := ui.NewErrorInfo(ui.CodeInternalError, userMsg).
			WithTitle("Internal error").
			WithAction(action).
			WithURL(metadata.IssuesRef())
		a.writeErrorInfo(errInfo)
		a.ExitFunc(ui.ExitInternal)
	}
}

func panicMessageFromValue(recovered any) string {
	switch value := recovered.(type) {
	case error:
		return value.Error()
	case string:
		return value
	default:
		return fmt.Sprintf("(panic type %T)", recovered)
	}
}

func (a *App) panicUserMessage(sanitized string) string {
	if a.Flags.Verbosity >= 2 {
		if a.Logger != nil {
			a.Logger.Error("panic recovered", "panic", sanitized)
		}
		return fmt.Sprintf("internal error: %s", sanitized)
	}
	if a.Logger != nil {
		a.Logger.Error("panic recovered")
	}
	return "internal error occurred; rerun with -vv to see details"
}

func (a *App) sanitizeExecuteMessage(message string) string {
	return a.sanitizer.ScrubMessage(message)
}
