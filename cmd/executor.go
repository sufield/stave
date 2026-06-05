package cmd

import (
	"context"
	"errors"
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
	// the caller's view at the pre-expansion alias name, so
	// session persistence keyed off "enf" instead of "enforce"
	// when the user invoked `stave enf ...`. Returning the
	// resolved argv keeps the two views in lockstep.
	expandedArgs := a.expandAliasIfMatch()
	// Guard the [1:] slice. expandAliasIfMatch normally returns os.Args
	// (length ≥ 1: the binary name) or `slices.Concat(tokens, os.Args[2:])`
	// from an alias expansion. The latter can be empty when the alias
	// resolves to nothing AND the user passed no extra args (e.g.
	// `stave myalias` where `myalias = ""`). Slicing [1:] on a
	// zero-length slice panics; treat the degenerate case as "no args"
	// rather than crashing the executor.
	var args []string
	if len(expandedArgs) > 0 {
		args = expandedArgs[1:]
	}

	cleanup := a.installInterruptHandler()
	a.cleanupInterrupt.Store(&cleanup)
	defer func() {
		if fn := a.cleanupInterrupt.Swap(nil); fn != nil {
			(*fn)()
		}
	}()
	defer a.recoverExecutePanic()

	a.executeRootCommand()

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

	a.finalizeExecute(args)
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
//     during alias expansion or
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

	// sync.Once-guarded closure. Both the deferred-cleanup path
	// (Execute → defer cleanupInterrupt), the panic-recovery path
	// (recoverExecutePanic explicitly invokes a.cleanupInterrupt
	// before ExitFunc), AND the pre-bootstrap signal goroutine path
	// share this single cleanup. Without the shared Once the second
	// invocation would `close(done)` a channel already closed by the
	// first and panic.
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			signal.Stop(sigCh)
			close(done)
		})
	}

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
				// Mirror the pre-bootstrap path below: flush the
				// CPU profile, close the log file, and write the
				// memory profile via cleanupBeforeExit BEFORE
				// returning. The main goroutine's deferred
				// cleanupBeforeExit will still fire and become a
				// no-op (sync.Once), so we don't double-flush;
				// running it from this goroutine guarantees the
				// flush happens even when the command's RunE is
				// blocked in a syscall the cancelled ctx cannot
				// unwind in time.
				a.cleanupBeforeExit()
				// Run cleanup explicitly so signal.Stop
				// unregisters the channel immediately. Without
				// this, a second SIGINT arriving before the main
				// goroutine's defer fires would be delivered to
				// Go's default handler (process termination
				// without our log-flush / profile-stop path).
				// The shared sync.Once makes this idempotent
				// with the main goroutine's eventual cleanup()
				// call.
				cleanup()
				// Force the process exit even if the main
				// goroutine is wedged inside a non-ctx-aware
				// syscall (e.g. a long disk read that the
				// cancelled ctx cannot unwind). The earlier shape
				// returned without exiting, deferring exit to the
				// main goroutine — fine when RunE actually wakes
				// up on ctx cancellation, but a hang otherwise.
				// ExitFunc IS the test seam for SIGINT handling,
				// so calling it here does not bypass any test
				// hooks. Mirrors the pre-bootstrap path below.
				a.ExitFunc(ui.ExitInterrupted)
				return
			}
			// Pre-bootstrap signal: cancel function not yet stored.
			// Run minimum cleanup ourselves before exiting so a
			// CPU profile started by an even earlier startCPUProfile
			// call (or a log file opened by phaseLogging) is closed
			// instead of left half-flushed on disk. Then run the
			// shared cleanup so the signal handler unregisters and
			// `done` closes — important when ExitFunc is mocked
			// (tests) and the process does not actually terminate;
			// otherwise sigCh stays registered and the goroutine
			// leaks.
			a.cleanupBeforeExit()
			cleanup()
			a.ExitFunc(ui.ExitInterrupted)
		case <-done:
			return
		}
	}()

	return cleanup
}

func (a *App) executeRootCommand() {
	if err := a.Root.Execute(); err != nil {
		err = a.suggestCommandIfUnknown(err)
		a.handleExecutionError(err)
	}
}

// suggestCommandIfUnknown replaces Cobra's generic "unknown command" error
// with a single best-match "Did you mean?" hint using the suggest package.
//
// A mistyped command name is always invalid INPUT (exit 2), so any
// "unknown command" error is wrapped in *ui.UserError — whether or not a
// close fuzzy match was found. When SuggestCommandError finds a match it
// returns an enhanced "Did you mean?" error; when it does not, it returns
// the original Cobra error unchanged. Both shapes start with the
// "unknown command " prefix and must map to ExitInputError, not the
// ExitInternal default that an unclassified raw error would otherwise hit.
func (a *App) suggestCommandIfUnknown(err error) error {
	names := collectVisibleCommandNames(a.Root)
	enhanced := ui.SuggestCommandError(err, names)
	if enhanced != err || isUnknownCommandError(err) { //nolint:errorlint // identity check: SuggestCommandError returns same pointer or new error
		return &ui.UserError{Err: enhanced}
	}
	return err
}

// isUnknownCommandError reports whether err carries Cobra's
// "unknown command ..." message shape.
func isUnknownCommandError(err error) bool {
	return err != nil && strings.HasPrefix(err.Error(), "unknown command ")
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

func (a *App) handleExecutionError(err error) {
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
	// Classify context-cancelled / deadline-exceeded as interrupts
	// rather than command failures: the command did not fault, the
	// outer context tore it down (SIGINT, parent timeout). Logging
	// these at the same level as a real command error makes
	// signal-driven shutdowns look like crashes in the audit trail.
	switch {
	case errors.Is(err, context.Canceled):
		logger.Info("command interrupted by context cancellation", "exit_code", exitCode)
	case errors.Is(err, context.DeadlineExceeded):
		logger.Info("command interrupted by deadline", "exit_code", exitCode)
	default:
		// Real command failures deserve warn-level visibility — the
		// previous Debug routing meant a non-default log level
		// dropped them entirely from operator-facing logs, so a
		// production-mode invocation produced an exit code with no
		// log line explaining why. Context-driven interrupts above
		// stay at Info because they are routine (Ctrl-C, parent
		// timeout) and not actionable.
		logger.Warn("command failed", "error", msg, "exit_code", exitCode)
	}

	// Sentinel errors (ErrViolationsFound, ErrSecurityAuditFindings,
	// ErrInterrupted) already had their user-facing output produced
	// by the command itself before returning, so writeCommandError
	// would print a duplicate "Violations detected" message under
	// the actual finding listing.
	//
	// Validation sentinels are emitted only by commands (`stave
	// validate-controls lint`, `stave apply --dry-run`, ...) that
	// have already printed their diagnostic listing to stdout —
	// duplicating with a structured stderr banner produced
	// confusing back-to-back failure messages. The contract: any
	// command that returns a validation sentinel must have
	// already produced operator-actionable output. Add a
	// validation command without that output → user sees only an
	// exit code; that's a contract bug in the command, not the
	// executor.
	if !isSentinelError(err) {
		// Non-sentinel: a command-level failure with no
		// pre-printed user output. Surface the structured
		// error block. Sentinels (finding + validation) skip
		// this entirely — the originating command already
		// printed the actionable diagnostics, so a stderr
		// banner duplicated the message.
		a.writeCommandError(err)
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
// would normally close (CPU profile, cancel func, mem profile, log
// file). Wrapped in cleanupOnce so concurrent invocations from the
// four call sites (handleExecutionError, recoverExecutePanic, signal
// handler, ctx-deadline finalizer) collapse to a single execution.
//
// bootstrapMu protects the LogCloser read against a race with
// phaseLogging's bootstrap-time assignment: a pre-bootstrap signal
// can fire before the logger is fully wired, and reading a
// half-assigned pointer field is a Go data race even if the
// underlying close is idempotent.
func (a *App) cleanupBeforeExit() {
	a.cleanupOnce.Do(func() {
		// Swap(nil) atomically takes ownership of the cancel func: a
		// concurrent peer racing cleanupBeforeExit gets nil here even
		// though the outer cleanupOnce normally serialises us.
		// context.CancelFunc is itself idempotent, but Swap publishes
		// the "already-cancelled" state so finalizeExecute (which also
		// calls Swap(nil)) does not double-invoke.
		if cancel := a.cancel.Swap(nil); cancel != nil {
			(*cancel)()
		}
		a.releaseResources(nil)
	})
}

func (a *App) finalizeExecute(args []string) {
	// Release the bootstrap-allocated context so its goroutine and any
	// timer associated with WithCancel are reclaimed. Without this, a
	// normal (non-signal) command exit leaves the cancelCtx pinned for
	// the lifetime of the process — fine for one-shot CLI runs but
	// observable in long-lived test harnesses that re-execute the
	// binary in-process. Swap(nil) hands off ownership atomically so a
	// peer cleanupBeforeExit racing us cannot also call cancel.
	if cancel := a.cancel.Swap(nil); cancel != nil {
		(*cancel)()
	}

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
