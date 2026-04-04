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
func Execute() {
	app := NewApp()
	app.execute()
}

// ExecuteDev runs the root command with the "dev" edition label.
func ExecuteDev() {
	app := NewApp(WithDevEdition())
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
		select {
		case <-sigCh:
			fmt.Fprintln(os.Stderr, "Interrupted")
			if a.cancel != nil {
				a.cancel()
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
	if enhanced != err {
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

	a.ExitFunc(exitCode)
}

func (a *App) finalizeExecute(args []string, showFirstRunHint bool, firstRunMarkerPath string) {
	markFirstRunHintSeenIfNeeded(showFirstRunHint, firstRunMarkerPath)
	a.printNoProjectHintIfNeeded(args)

	resolver, _ := projctx.NewResolver()
	projectRoot := persistSessionStateIfApplicable(resolver, args)
	a.printWorkflowHandoff(args, projectRoot)
}
