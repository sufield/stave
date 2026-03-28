package cmd

import (
	"fmt"
	"runtime/debug"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/metadata"
)

func (a *App) recoverExecutePanic() {
	if recovered := recover(); recovered != nil {
		stack := debug.Stack()

		panicMsg := panicMessageFromValue(recovered)
		sanitized := a.sanitizeExecuteMessage(panicMsg)

		if a.Logger != nil {
			a.Logger.Error("panic recovered",
				"panic", sanitized,
				"stack", string(stack),
			)
		}

		errInfo := a.buildPanicErrorInfo(sanitized)
		a.writeErrorInfo(errInfo)
		a.ExitFunc(ui.ExitInternal)
	}
}

func (a *App) buildPanicErrorInfo(sanitized string) *ui.ErrorInfo {
	userMsg := "internal error occurred; rerun with -vv to see details"
	if a.Flags.Verbosity >= 2 {
		userMsg = fmt.Sprintf("internal error: %s", sanitized)
	}

	action := "Rerun with -vv, then run `stave-dev doctor` or contact support if this error persists."
	if a.Edition == EditionDev {
		action = "Rerun with -vv, then run `stave bug-report` and attach the bundle if it persists."
	}

	return ui.NewErrorInfo(ui.CodeInternalError, userMsg).
		WithTitle("Internal error").
		WithAction(action).
		WithURL(metadata.IssuesRef())
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

func (a *App) sanitizeExecuteMessage(message string) string {
	return a.sanitizer.ScrubMessage(message)
}
