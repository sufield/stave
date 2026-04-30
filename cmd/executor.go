package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/projctx"
	"github.com/sufield/stave/internal/cli/ui"
)

// Execute runs the production root command and handles exit codes appropriately.
// It sets up SIGINT handling, executes the root command, and exits with
// the appropriate exit code based on the result.
// Panics are recovered and converted to error messages to prevent stack traces.
// Wiring errors from NewApp surface as a single-line stderr message + exit 4
// rather than a panic stack trace.
func Execute() {
	app, err := NewApp()
	if err != nil {
		fmt.Fprintf(os.Stderr, "stave: wire commands: %v\n", err)
		os.Exit(ui.ExitInternal)
	}
	app.execute()
}

// ExecuteDev runs the root command with the "dev" edition label.
func ExecuteDev() {
	app, err := NewApp(WithDevEdition())
	if err != nil {
		fmt.Fprintf(os.Stderr, "stave: wire commands: %v\n", err)
		os.Exit(ui.ExitInternal)
	}
	app.execute()
}

func (a *App) execute() {
	args := os.Args[1:]

	a.expandAliasIfMatch()

	showFirstRunHint, firstRunMarkerPath := prepareFirstRunHint(args)

	a.cleanupInterrupt = a.installInterruptHandler()
	defer func() {
		if a.cleanupInterrupt != nil {
			a.cleanupInterrupt()
		}
	}()
	defer a.recoverExecutePanic()

	a.executeRootCommand(args)

	// If a signal canceled the root context, exit with the interrupt code.
	// Deferred cleanup (cleanupInterrupt, recoverExecutePanic) runs normally.
	if a.Root.Context() != nil && a.Root.Context().Err() != nil {
		a.ExitFunc(ui.ExitInterrupted)
		return
	}

	a.finalizeExecute(args, showFirstRunHint, firstRunMarkerPath)
}

// installInterruptHandler uses os.Stderr directly because signal handlers
// run outside the Cobra command lifecycle — cmd.ErrOrStderr() is not available.
func (a *App) installInterruptHandler() func() {
	sigCh := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "signal handler panic: %v\n", r)
			}
		}()
		select {
		case <-sigCh:
			fmt.Fprintln(os.Stderr, "Interrupted")
			if cancel := a.cancel.Load(); cancel != nil {
				(*cancel)()
			} else {
				// Pre-bootstrap signal: context not yet available.
				a.ExitFunc(ui.ExitInterrupted)
			}
		case <-done:
			return
		}
	}()

	return func() {
		signal.Stop(sigCh)
		close(done)
	}
}

func (a *App) executeRootCommand(args []string) {
	if err := a.Root.Execute(); err != nil {
		err = a.suggestCommandIfUnknown(err)
		a.handleExecutionError(err, args)
	}
}

// suggestCommandIfUnknown replaces Cobra's generic "unknown command" error
// with a single best-match "Did you mean?" hint using the suggest package.
func (a *App) suggestCommandIfUnknown(err error) error {
	names := collectVisibleCommandNames(a.Root)
	enhanced := ui.SuggestCommandError(err, names)
	if enhanced != err { //nolint:errorlint // identity check: SuggestCommandError returns same pointer or new error
		return &ui.UserError{Err: enhanced}
	}
	return err
}

// collectVisibleCommandNames returns the names of all non-hidden subcommands.
func collectVisibleCommandNames(root *cobra.Command) []string {
	var names []string
	for _, c := range root.Commands() {
		if !c.Hidden {
			names = append(names, c.Name())
		}
	}
	return names
}

func (a *App) handleExecutionError(err error, args []string) {
	exitCode := ExitCode(err)

	if a.Logger != nil {
		// Log only the root error message, not presentation decoration
		// (Next: …, More info: … lines appended by hint wrappers).
		msg := err.Error()
		if idx := strings.Index(msg, "\n"); idx > 0 {
			msg = msg[:idx]
		}
		a.Logger.Debug("command failed", "error", msg, "exit_code", exitCode)
	}

	if !isSentinelError(err) {
		a.writeCommandError(err, args)
	}

	// postRun is skipped on the error-exit path (Cobra's RunE returned
	// non-nil before postRun could fire), so stop the CPU profile and
	// close the log file ourselves. Mirrors recoverExecutePanic's
	// cleanup order; without it a long-running CI run that errored
	// would leave a half-written cpuprofile and lose any buffered
	// audit log entries describing the failure itself.
	a.cleanupBeforeExit()

	a.ExitFunc(exitCode)
}

// cleanupBeforeExit releases process-level resources that postRun
// would normally close (CPU profile, log file). Idempotent: each
// underlying close is itself idempotent (LogCloser uses sync.Once,
// stopCPUProfile no-ops if no profile is active).
func (a *App) cleanupBeforeExit() {
	a.stopCPUProfile()
	if a.LogCloser != nil {
		_ = a.LogCloser.Close()
	}
}

func (a *App) finalizeExecute(args []string, showFirstRunHint bool, firstRunMarkerPath string) {
	// Release the bootstrap-allocated context so its goroutine and any
	// timer associated with WithCancel are reclaimed. Without this, a
	// normal (non-signal) command exit leaves the cancelCtx pinned for
	// the lifetime of the process — fine for one-shot CLI runs but
	// observable in long-lived test harnesses that re-execute the
	// binary in-process.
	if cancel := a.cancel.Load(); cancel != nil {
		(*cancel)()
	}
	markFirstRunHintSeenIfNeeded(showFirstRunHint, firstRunMarkerPath)
	a.printNoProjectHintIfNeeded(args)

	// Resolver failures are non-fatal during finalization — the rest of
	// the command already ran successfully; we just lose
	// session-state persistence and the workflow-handoff hint. Log the
	// reason at Warn so operators can correlate missing hints with the
	// underlying cause.
	resolver, resolverErr := projctx.NewResolver()
	if resolverErr != nil && a.Logger != nil {
		a.Logger.Warn("project resolver init failed during finalize",
			"error", resolverErr)
	}
	projectRoot := persistSessionStateIfApplicable(resolver, args)
	a.printWorkflowHandoff(args, projectRoot)
}
