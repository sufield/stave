package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
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
	// Capture args from the alias-expansion return so downstream
	// consumers see the resolved command name. Root.SetArgs writes
	// to Cobra's internal slot but does NOT mutate os.Args; the
	// earlier `args := os.Args[1:]` after expandAliasIfMatch left
	// the caller's view at the pre-expansion alias name, so the
	// first-run hint, no-project hint, and session persistence
	// all keyed off "enf" instead of "enforce" when the user
	// invoked `stave enf ...`. Returning the resolved argv keeps
	// the two views in lockstep.
	expandedArgs := a.expandAliasIfMatch()
	args := expandedArgs[1:]

	showFirstRunHint, firstRunMarkerPath := prepareFirstRunHint(args)

	cleanup := a.installInterruptHandler()
	a.cleanupInterrupt.Store(&cleanup)
	defer func() {
		if fn := a.cleanupInterrupt.Swap(nil); fn != nil {
			(*fn)()
		}
	}()
	defer a.recoverExecutePanic()

	a.executeRootCommand(args)

	// If a signal canceled the root context, exit with the interrupt code.
	// Deferred cleanup (cleanupInterrupt, recoverExecutePanic) runs
	// normally; cleanupBeforeExit handles the same flush/profile-stop
	// pair handleExecutionError and recoverExecutePanic share, so a
	// SIGINT exit path matches the other two for log/profile fidelity.
	if a.Root.Context() != nil && a.Root.Context().Err() != nil {
		a.cleanupBeforeExit()
		a.ExitFunc(ui.ExitInterrupted)
		return
	}

	a.finalizeExecute(args, showFirstRunHint, firstRunMarkerPath)
}

// installInterruptHandler uses os.Stderr directly because signal handlers
// run outside the Cobra command lifecycle — cmd.ErrOrStderr() is not available.
//
// Signal-arrival timing breaks down into two windows:
//
//  1. Post-bootstrap: phaseContext has stored the cancel function on
//     a.cancel. The handler cancels the root context, RunE returns
//     with ctx.Err()==Canceled, finalizeExecute runs the normal
//     cleanup path, and the process exits.
//  2. Pre-bootstrap: phaseContext has not run yet (signal landed
//     during alias expansion, first-run hint setup, or
//     installInterruptHandler itself). a.cancel is nil and there is
//     no in-flight Cobra command to cancel — the handler runs the
//     same cleanupBeforeExit as the normal path and then exits.
//
// Both windows print "Interrupted" to stderr so the operator gets a
// consistent message regardless of timing.
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
				// Returning here is safe: the cleanup closure
				// returned by installInterruptHandler (and called
				// from the main goroutine's defer + the panic
				// recovery path) is what calls signal.Stop and
				// close(done). The signal.Stop call must NOT be
				// duplicated here — sync.Once in the closure
				// already serializes it, but doubling the
				// Notify→Stop pair across goroutines without
				// shared coordination would race. The goroutine
				// simply exits; cleanup is the closure's job.
				return
			}
			// Pre-bootstrap signal: cancel function not yet stored.
			// Run minimum cleanup ourselves before exiting so a
			// CPU profile started by an even earlier startCPUProfile
			// call (or a log file opened by phaseLogging) is closed
			// instead of left half-flushed on disk.
			a.cleanupBeforeExit()
			a.ExitFunc(ui.ExitInterrupted)
		case <-done:
			return
		}
	}()

	// sync.Once-guarded closure. Both the deferred-cleanup path
	// (Execute → defer cleanupInterrupt) and the panic-recovery
	// path (recoverExecutePanic explicitly invokes
	// a.cleanupInterrupt before ExitFunc) can reach this closure;
	// without the Once, the second invocation would
	// `close(done)` a channel already closed by the first and
	// panic the goroutine that's tearing the process down.
	var once sync.Once
	return func() {
		once.Do(func() {
			signal.Stop(sigCh)
			close(done)
		})
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

	// Log only the root error message, not presentation decoration
	// (Next: …, More info: … lines appended by hint wrappers).
	logger := a.Logger
	if logger == nil {
		// Bootstrap can fail before the structured logger is wired
		// up (config resolution error, env-var parse error, etc.).
		// Falling back to slog.Default() ensures those early-phase
		// errors land *somewhere* — the previous nil-guard simply
		// dropped them, so a failed startup looked indistinguishable
		// from a successful one until the user noticed the exit
		// code.
		logger = slog.Default()
	}
	msg := err.Error()
	if idx := strings.Index(msg, "\n"); idx > 0 {
		msg = msg[:idx]
	}
	logger.Debug("command failed", "error", msg, "exit_code", exitCode)

	// Sentinel errors (ErrViolationsFound, ErrSecurityAuditFindings,
	// ErrInterrupted) already had their user-facing output produced
	// by the command itself before returning, so writeCommandError
	// would print a duplicate "Violations detected" message under
	// the actual finding listing. Validation errors are different:
	// the validation command often returns the sentinel without
	// having printed anything user-facing, so the operator sees
	// only an exit code with no explanation. Surface those
	// explicitly via writeCommandError, keeping the silent-on-
	// finding-sentinels behavior for the rest.
	if !isSentinelError(err) || isValidationSentinel(err) {
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
//
// bootstrapMu protects the LogCloser read against a race with
// phaseLogging's bootstrap-time assignment: a pre-bootstrap signal
// can fire before the logger is fully wired, and reading a
// half-assigned pointer field is a Go data race even if the
// underlying close is idempotent.
func (a *App) cleanupBeforeExit() {
	a.stopCPUProfile()
	// Mirror finalizeExecute: invoke the bootstrap-allocated cancel
	// so the cancelCtx goroutine + any associated timer are reclaimed
	// even on the error path. The earlier shape released cancel only
	// in finalizeExecute (the success path), leaving long-lived
	// in-process callers (test harnesses re-executing the binary)
	// with a leaked cancelCtx per failed run.
	if cancel := a.cancel.Load(); cancel != nil {
		(*cancel)()
	}
	// Write the memory profile on error too. The success path runs
	// it via postRun -> writeMemProfile; without this hook a command
	// that crashed before postRun never produced the requested
	// --mem-profile artifact, hiding the very allocation pattern an
	// operator was trying to capture.
	a.writeMemProfileTo(os.Stderr)
	a.bootstrapMu.Lock()
	closer := a.LogCloser
	a.bootstrapMu.Unlock()
	if closer != nil {
		if err := closer.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: close log file: %v\n", err)
		}
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
	if resolverErr != nil {
		// Match handleExecutionError / recoverExecutePanic: a
		// finalize-time failure that happens before the structured
		// logger is wired (or after it has been torn down) used
		// to drop the warning silently. Falling back to
		// slog.Default ensures the reason still lands somewhere
		// — silence here masks correlated downstream symptoms
		// (missing session-state persistence, no workflow hint).
		logger := a.Logger
		if logger == nil {
			logger = slog.Default()
		}
		logger.Warn("project resolver init failed during finalize",
			"error", resolverErr)
		// Skip both downstream calls when resolver init failed.
		// persistSessionStateIfApplicable would have to nil-check
		// resolver internally on every access, and printWorkflowHandoff
		// reads the resolver-derived project root — both produce
		// degenerate output when the resolver is nil. Return early so
		// the operator gets the warning without the secondary noise.
		return
	}
	projectRoot := persistSessionStateIfApplicable(resolver, args)
	a.printWorkflowHandoff(args, projectRoot)
}
