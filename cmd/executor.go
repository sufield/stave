package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	"github.com/sufield/stave/cmd/enforce"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/state"
)

// Execute runs the root command and handles exit codes appropriately.
// It sets up SIGINT handling, executes the root command, and exits with
// the appropriate exit code based on the result.
// Panics are recovered and converted to error messages to prevent stack traces.
func Execute() {
	app := NewApp()
	app.execute()
}

func (a *App) execute() {
	args := os.Args[1:]

	a.expandAliasIfMatch()

	showFirstRunHint, firstRunMarkerPath := prepareFirstRunHint(args)

	cleanupInterrupt := a.installInterruptHandler()
	defer cleanupInterrupt()
	defer a.recoverExecutePanic()

	a.executeRootCommand(args)
	a.finalizeExecute(args, showFirstRunHint, firstRunMarkerPath)
}

func (a *App) installInterruptHandler() func() {
	sigCh := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		select {
		case <-sigCh:
			fmt.Fprintln(os.Stderr, "Interrupted")
			a.ExitFunc(ui.ExitInterrupted)
		case <-done:
			return
		}
	}()

	return func() {
		signal.Stop(sigCh)
		close(done)
	}
}

func (a *App) recoverExecutePanic() {
	if recovered := recover(); recovered != nil {
		panicMsg := panicMessageFromValue(recovered)
		sanitized := a.sanitizeExecuteMessage(panicMsg)
		userMsg := a.panicUserMessage(sanitized)

		errInfo := ui.NewErrorInfo(ui.CodeInternalError, userMsg).
			WithTitle("Internal error").
			WithAction("Rerun with -vv, then run `stave bug-report` and attach the bundle if it persists.").
			WithURL(CLIIssuesURL)
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
	if !a.resolvePathSanitize() {
		return message
	}
	return ui.SanitizePaths(message)
}

func (a *App) executeRootCommand(args []string) {
	err := a.Root.Execute()
	if err == nil {
		return
	}
	if a.Logger != nil {
		a.Logger.Debug("command failed", "error", err.Error())
	}
	if !isSentinelError(err) {
		a.writeCommandError(err, args)
	}
	a.ExitFunc(ExitCode(err))
}

func (a *App) writeCommandError(err error, args []string) {
	errMsg := ensureFirstRunRunHint(err.Error(), args)
	errMsg = a.sanitizeExecuteMessage(errMsg)
	a.writeErrorInfo(errorInfoFromError(err, errMsg))
}

func (a *App) finalizeExecute(args []string, showFirstRunHint bool, firstRunMarkerPath string) {
	markFirstRunHintSeenIfNeeded(showFirstRunHint, firstRunMarkerPath)
	a.printNoProjectHintIfNeeded(args)
	projectRoot := persistSessionStateIfApplicable(args)
	a.printWorkflowHandoff(args, projectRoot)
}

func markFirstRunHintSeenIfNeeded(show bool, markerPath string) {
	if show && markerPath != "" {
		// Best-effort: failure to persist the marker is harmless; the hint just shows again.
		_ = state.MarkFirstRunSeen(markerPath)
	}
}

func (a *App) printNoProjectHintIfNeeded(args []string) {
	if len(args) != 0 {
		return
	}
	if _, found := projconfig.FindNearestFile(projconfig.ProjectConfigFile); !found {
		fmt.Fprintf(a.Root.ErrOrStderr(), "No Stave project found in this directory tree. Run `%s` to create one.\n", cliCommand("init"))
	}
}

func persistSessionStateIfApplicable(args []string) string {
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}
	projectRoot, detectErr := projctx.DetectProjectRoot(cwd)
	if detectErr != nil {
		return ""
	}
	// Best-effort: session state is advisory; failure doesn't affect the command result.
	_ = projctx.SaveSessionState(projectRoot, args)
	return projectRoot
}

func (a *App) printWorkflowHandoff(args []string, projectRoot string) {
	rt := ui.NewRuntime(nil, nil)
	rt.Quiet = a.Flags.Quiet
	rt.PrintWorkflowHandoff(ui.WorkflowHandoffRequest{
		Args:        args,
		ProjectRoot: projectRoot,
		NextCommand: enforce.NextCommandForProject,
	})
}

func prepareFirstRunHint(args []string) (bool, string) {
	if ui.ShouldSkipFirstRunHint(args) {
		return false, ""
	}
	markerPath, err := state.FirstRunMarkerPath()
	if err != nil {
		return false, ""
	}
	if _, statErr := os.Stat(markerPath); os.IsNotExist(statErr) {
		fmt.Fprintln(os.Stderr, ui.FirstRunHintMessage)
		return true, markerPath
	}
	return false, markerPath
}

func ensureFirstRunRunHint(message string, args []string) string {
	if strings.Contains(message, "\nRun:") {
		return message
	}
	if len(args) == 0 {
		return message
	}
	switch args[0] {
	case "demo", "quickstart", "init", "doctor", "status":
		return fmt.Sprintf("%s\nRun: %s --help", message, cliCommand(args[0]))
	default:
		return message
	}
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
	case ui.IsInputError(err):
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

func (a *App) writeErrorInfo(errInfo *ui.ErrorInfo) {
	if errInfo == nil {
		return
	}
	// Best-effort: if we can't display the error, there's nothing else to try.
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
