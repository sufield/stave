package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/sufield/stave/cmd/cmdutil"
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
	args := os.Args[1:]

	expandAliasIfMatch()

	showFirstRunHint, firstRunMarkerPath := prepareFirstRunHint(args)

	cleanupInterrupt := installInterruptHandler()
	defer cleanupInterrupt()
	defer recoverExecutePanic()

	executeRootCommand(args)
	finalizeExecute(args, showFirstRunHint, firstRunMarkerPath)
}

func installInterruptHandler() func() {
	sigCh := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		select {
		case <-sigCh:
			fmt.Fprintln(os.Stderr, "Interrupted")
			exitFunc(ui.ExitInterrupted)
		case <-done:
			return
		}
	}()

	return func() {
		signal.Stop(sigCh)
		close(done)
	}
}

func recoverExecutePanic() {
	if recovered := recover(); recovered != nil {
		panicMsg := panicMessageFromValue(recovered)
		sanitized := sanitizeExecuteMessage(panicMsg)
		userMsg := panicUserMessage(sanitized)

		errInfo := ui.NewErrorInfo(ui.CodeInternalError, userMsg).
			WithTitle("Internal error").
			WithAction("Rerun with -vv, then run `stave bug-report` and attach the bundle if it persists.").
			WithURL(CLIIssuesURL)
		writeErrorInfo(errInfo)
		exitFunc(ui.ExitInternal)
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

func panicUserMessage(sanitized string) string {
	if gFlags.Verbosity >= 2 {
		if globalLogger != nil {
			globalLogger.Error("panic recovered", "panic", sanitized)
		}
		return fmt.Sprintf("internal error: %s", sanitized)
	}
	if globalLogger != nil {
		globalLogger.Error("panic recovered")
	}
	return "internal error occurred; rerun with -vv to see details"
}

func sanitizeExecuteMessage(message string) string {
	if !resolvePathSanitize() {
		return message
	}
	return ui.SanitizePaths(message)
}

func executeRootCommand(args []string) {
	err := RootCmd.Execute()
	if err == nil {
		return
	}
	if globalLogger != nil {
		globalLogger.Debug("command failed", "error", err.Error())
	}
	if !isSentinelError(err) {
		writeCommandError(err, args)
	}
	exitFunc(ExitCode(err))
}

func writeCommandError(err error, args []string) {
	errMsg := ensureFirstRunRunHint(err.Error(), args)
	errMsg = sanitizeExecuteMessage(errMsg)
	writeErrorInfo(errorInfoFromError(err, errMsg))
}

func finalizeExecute(args []string, showFirstRunHint bool, firstRunMarkerPath string) {
	markFirstRunHintSeenIfNeeded(showFirstRunHint, firstRunMarkerPath)
	printNoProjectHintIfNeeded(args)
	projectRoot := persistSessionStateIfApplicable(args)
	printWorkflowHandoff(args, projectRoot)
}

func markFirstRunHintSeenIfNeeded(show bool, markerPath string) {
	if show && markerPath != "" {
		_ = state.MarkFirstRunSeen(markerPath)
	}
}

func printNoProjectHintIfNeeded(args []string) {
	if len(args) != 0 {
		return
	}
	if _, found := cmdutil.FindNearestFile(cmdutil.ProjectConfigFile); !found {
		fmt.Fprintf(os.Stderr, "No Stave project found in this directory tree. Run `%s` to create one.\n", cliCommand("init"))
	}
}

func persistSessionStateIfApplicable(args []string) string {
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}
	projectRoot, detectErr := cmdutil.DetectProjectRoot(cwd)
	if detectErr != nil {
		return ""
	}
	_ = cmdutil.SaveSessionState(projectRoot, args)
	return projectRoot
}

func printWorkflowHandoff(args []string, projectRoot string) {
	rt := ui.NewRuntime(nil, nil)
	rt.Quiet = gFlags.Quiet
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
		return ui.NewErrorInfo("SECURITY_AUDIT_FINDINGS", message).
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

func writeErrorInfo(errInfo *ui.ErrorInfo) {
	if errInfo == nil {
		return
	}
	if IsJSONMode() {
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
