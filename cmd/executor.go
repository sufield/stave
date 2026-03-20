package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

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

func (a *App) finalizeExecute(args []string, showFirstRunHint bool, firstRunMarkerPath string) {
	markFirstRunHintSeenIfNeeded(showFirstRunHint, firstRunMarkerPath)
	a.printNoProjectHintIfNeeded(args)
	projectRoot := persistSessionStateIfApplicable(args)
	a.printWorkflowHandoff(args, projectRoot)
}
