package cmd

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"runtime/pprof"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/cmdctx"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	predicates "github.com/sufield/stave/internal/adapters/predicate"
	appconfig "github.com/sufield/stave/internal/app/config"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/evaluation/exposure"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/env"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/platform/logging"
)

// bootstrapPhase is a named step in the bootstrap pipeline.
type bootstrapPhase struct {
	Name string
	Run  func(cmd *cobra.Command) error
}

// bootstrap runs as PersistentPreRunE on every command.
// It executes a declared pipeline of phases in order.
func (a *App) bootstrap(cmd *cobra.Command, _ []string) error {
	for _, p := range a.bootstrapPipeline() {
		if err := p.Run(cmd); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) bootstrapPipeline() []bootstrapPhase {
	return []bootstrapPhase{
		{"context", a.phaseContext},
		{"config", a.phaseConfig},
		{"validate", a.phaseValidate},
		{"logging", a.phaseLogging},
		{"enrich", a.phaseEnrich},
	}
}

// phaseContext sets up the cancelable root context and validates builtins.
func (a *App) phaseContext(cmd *cobra.Command) error {
	ctx, cancel := context.WithCancel(cmd.Context()) //nolint:gosec // cancel stored on a.cancel, called by signal handler
	a.cancel.Store(&cancel)
	cmd.SetContext(ctx)

	if err := a.startCPUProfile(); err != nil {
		return err
	}
	return a.validateBuiltins()
}

// phaseConfig resolves flag defaults from project/user config and env vars.
//
// resolveConfigurableLimits intentionally does NOT run here. The
// limits resolver may emit Warn lines (e.g. "ignoring invalid
// max_input_file_size"); routing those through the structured
// logger requires a.Logger to be wired, which only happens in
// phaseLogging. The earlier shape called resolveConfigurableLimits
// here and silently routed every warning through slog.Default()
// because a.Logger was still nil. Moved into phaseLogging below.
func (a *App) phaseConfig(cmd *cobra.Command) error {
	a.configResult = projconfig.BuildResolver()
	// Surface a config-load failure immediately for commands that
	// require config. The earlier shape stored the error on
	// configResult.Err and deferred the check to phaseValidate via
	// checkConfigHealth — meaning phaseLogging (and any work
	// scheduled before phaseValidate) ran against a broken config
	// state. Surfacing here aborts the pipeline at the first
	// reasonable boundary; phaseValidate's checkConfigHealth call
	// is now redundant but is retained as a defence-in-depth
	// catch in case a future refactor reintroduces a path that
	// skips phaseConfig.
	if err := a.checkConfigHealth(cmd, a.configResult.Err); err != nil {
		return err
	}
	a.resolveGlobalFlagDefaults(cmd, a.configResult.Resolver)
	a.resolveEnvVarDefaults(cmd)
	return nil
}

// phaseValidate checks the offline guarantee, dev/prod guard, and config health.
func (a *App) phaseValidate(cmd *cobra.Command) error {
	if err := a.checkRequireOffline(); err != nil {
		return err
	}
	if err := a.checkDevProductionGuard(cmd); err != nil {
		return err
	}
	return a.checkConfigHealth(cmd, a.configResult.Err)
}

// phaseLogging initializes the sanitizer, structured logger, and replays config warnings.
func (a *App) phaseLogging(_ *cobra.Command) error {
	ui.SetNoColor(a.Flags.NoColor)
	a.initSanitizer()
	if err := a.initLogger(); err != nil {
		return err
	}
	for _, w := range a.configResult.Warnings {
		a.Logger.Warn("config load warning", "error", w)
	}
	// Resolve configurable limits AFTER initLogger so any warnings
	// the resolver emits (invalid max_input_file_size, etc.) flow
	// through the structured logger rather than slog.Default(). The
	// limits themselves are pure setters with no dependency on the
	// logger; only the diagnostic path required this ordering fix.
	a.resolveConfigurableLimits(a.configResult.Resolver)
	return nil
}

// phaseEnrich stores the logger in the Cobra context for command retrieval.
func (a *App) phaseEnrich(cmd *cobra.Command) error {
	ctx := cmdctx.WithLogger(cmd.Context(), a.Logger)
	cmd.SetContext(ctx)
	return nil
}

// resolveGlobalFlagDefaults fills global persistent flags with project-config
// defaults when the user did not set them explicitly on the command line.
// The resolver is stored in Cobra's context so all downstream commands
// retrieve it via cmdctx.ResolverFromCmd(cmd).
func (a *App) resolveGlobalFlagDefaults(cmd *cobra.Command, eval *appconfig.GovernanceResolver) {
	// Bootstrap can hand a nil resolver when project-config loading
	// failed and the command is annotated as config-optional.
	// Calling eval.Quiet() / Sanitize() / PathMode() on nil panics;
	// in the optional-config case the right behaviour is to fall
	// back to whatever defaults the persistent flags already carry.
	//
	// The early return runs BEFORE cmdctx.WithResolver(ctx, eval) so
	// downstream commands looking up the resolver via
	// cmdctx.ResolverFromCmd never observe a typed-nil
	// (*GovernanceResolver)(nil) stored in the context — that form
	// of nil produces NPEs at every method call site, hiding the
	// "no resolver" semantic the caller intended.
	if eval == nil {
		slog.Debug("resolveGlobalFlagDefaults: config resolver is nil, skipping")
		return
	}
	ctx := cmdctx.WithResolver(cmd.Context(), eval)
	cmd.SetContext(ctx)

	p := cmd.Root().PersistentFlags()
	eval.ApplyUnsetDefaultsTo(&a.Flags, p.Changed)
}

// resolveEnvVarDefaults fills global persistent flags from STAVE_* environment
// variables when the user did not set them explicitly on the command line.
// Precedence: CLI flag > env var > config file > default.
// This runs after resolveGlobalFlagDefaults so env vars override config-file
// defaults but not explicit CLI flags.
func (a *App) resolveEnvVarDefaults(cmd *cobra.Command) {
	p := cmd.Root().PersistentFlags()

	if !p.Changed(cliflags.FlagQuiet) {
		if env.Quiet.IsTrue() {
			a.Flags.Quiet = true
		}
	}
}

// checkConfigHealth enforces config loading errors for commands that need config.
// Commands annotated with AnnotationConfigOptional tolerate config failures.
// cfgErr is the error from BuildResolver().
func (a *App) checkConfigHealth(cmd *cobra.Command, cfgErr error) error {
	if cfgErr == nil {
		return nil
	}
	if hasAnnotation(cmd, cmdutil.AnnotationConfigOptional) {
		return nil
	}
	// Cobra's built-in help command cannot be annotated at definition time.
	if cmd.Name() == "help" {
		return nil
	}
	return &ui.UserError{Err: fmt.Errorf(
		"project configuration is invalid: %w\n"+
			"Fix: check stave.yaml syntax or run 'stave config show' to inspect",
		cfgErr,
	)}
}

// hasAnnotation returns true if the command or any ancestor has the given
// annotation set to "true". This allows parent commands to mark all children
// as config-optional.
func hasAnnotation(cmd *cobra.Command, key string) bool {
	for c := cmd; c != nil; c = c.Parent() {
		if v, ok := c.Annotations[key]; ok && v == "true" {
			return true
		}
	}
	return false
}

func (a *App) postRun(cmd *cobra.Command, _ []string) {
	// No-op: resources are released at the end of execute() to avoid closing
	// the log file before finalizeExecute runs.
}

// releaseResources stops the CPU profile, writes the memory profile,
// and closes the log file. Called from both the normal exit path
// (postRun) and the error/signal path (cleanupBeforeExit). Each
// individual method has its own idempotency guard so calling both
// paths is safe.
func (a *App) releaseResources(cmd *cobra.Command) {
	a.stopCPUProfile()
	if cmd != nil {
		a.writeMemProfile(cmd)
	} else {
		a.writeMemProfileTo(os.Stderr)
	}
	a.closeLogCloser()
}

// closeLogCloser closes the bootstrap-attached LogCloser exactly
// once across postRun (normal exit) and cleanupBeforeExit (panic /
// signal / ctx-deadline finalizer). Reading a.LogCloser is guarded
// by bootstrapMu because phaseLogging assigns the field under the
// same mutex; the close + stderr warning are wrapped in
// logCloseOnce so a duplicate Close() call from the second path
// does not re-surface a stale failure as a second
// "Warning: close log file" line.
func (a *App) closeLogCloser() {
	a.logCloseOnce.Do(func() {
		a.bootstrapMu.Lock()
		closer := a.LogCloser
		a.bootstrapMu.Unlock()
		if closer == nil {
			return
		}
		if err := closer.Close(); err != nil {
			// LogCloser.Close failure means the log file's
			// final flush didn't reach disk. Surface via stderr
			// so an operator running with --log-file knows the
			// captured run may be truncated. Mirrors the
			// writeMemProfileTo fallback pattern.
			fmt.Fprintf(os.Stderr, "Warning: close log file: %v\n", err)
		}
	})
}

func (a *App) startCPUProfile() error {
	// ProfilerConfig returns (cpuPath, memPath); memPath is read
	// later by writeMemProfileTo via its own call. Naming the
	// discarded value documents the discard so a future reader
	// doesn't mistake `_` for an error capture (no error channel
	// exists on ProfilerConfig — path validation would happen here
	// via SafeCreateFile, and a malformed path surfaces as a
	// "create CPU profile" wrapped error below).
	cpuPath, _ /* memPath, see writeMemProfileTo */ := a.Flags.ProfilerConfig()
	if cpuPath == "" {
		return nil
	}
	opts := fsutil.DefaultWriteOpts()
	opts.Overwrite = true
	opts.AllowSymlink = a.Flags.AllowSymlinkOut
	f, err := fsutil.SafeCreateFile(cpuPath, opts)
	if err != nil {
		// Surface the activation failure to stderr in addition to
		// the returned error: the bootstrap path that calls us
		// returns the error and exits, but in test harnesses or
		// embedded use that swallow the error, the operator
		// should still see why profiling did not activate.
		fmt.Fprintf(os.Stderr,
			"Warning: --cpu-profile %q could not be opened (%v); profiling is not active\n", cpuPath, err)
		return fmt.Errorf("create CPU profile: %w", err)
	}
	if err := pprof.StartCPUProfile(f); err != nil {
		if closeErr := f.Close(); closeErr != nil {
			slog.Debug("close cpu profile file after StartCPUProfile failure",
				"error", closeErr)
		}
		return fmt.Errorf("start CPU profile: %w", err)
	}
	a.cpuProfileFile.Store(f)
	return nil
}

func (a *App) stopCPUProfile() {
	// Atomic swap-to-nil is the load-and-take pattern: whichever
	// concurrent caller wins the swap closes the file; the other
	// gets nil and no-ops. Without this, two stop paths firing
	// near-simultaneously (panic recovery + post-run, or signal
	// handler + finalize) would both call f.Close() on the same
	// descriptor — undefined-behavior double-close.
	f := a.cpuProfileFile.Swap(nil)
	if f == nil {
		return
	}
	pprof.StopCPUProfile()
	if err := f.Close(); err != nil {
		// Mirror the memory-profile path: a CPU profile that fails
		// to flush is a diagnostic gap, not a fatal one. Log so the
		// silent-truncation case becomes visible without changing
		// the existing fire-and-forget contract. Fall back to
		// slog.Default when a.Logger is nil — same pattern as
		// recoverExecutePanic — so panic / signal paths still
		// surface the warning before the logger is wired.
		if a.Logger != nil {
			a.Logger.Warn("close CPU profile", "error", err)
		} else {
			slog.Default().Warn("close CPU profile", "error", err)
		}
	}
}

func (a *App) writeMemProfile(cmd *cobra.Command) {
	var stderr io.Writer
	if cmd != nil {
		stderr = cmd.ErrOrStderr()
	}
	a.writeMemProfileTo(stderr)
}

// writeMemProfileTo is the cmd-independent body of writeMemProfile.
// The error-path cleanup (cleanupBeforeExit) calls this directly so
// the profile is written even when the command failed before
// finalizeExecute ran. stderr may be nil; it is used only as the
// fallback when a.Logger is also nil.
func (a *App) writeMemProfileTo(stderr io.Writer) {
	_, memPath := a.Flags.ProfilerConfig()
	if memPath == "" {
		return
	}
	// Idempotency: a panic mid-run lands in both recoverExecutePanic
	// and the deferred finalize path; without the CAS guard the
	// second writer truncates the first writer's output.
	if !a.memProfileWritten.CompareAndSwap(false, true) {
		return
	}
	warnf := func(msg string, err error) {
		if a.Logger != nil {
			a.Logger.Warn(msg, "error", err)
			return
		}
		if stderr == nil {
			// Fall back to os.Stderr so a profile-write failure with
			// neither logger nor command-bound stderr still produces
			// a visible diagnostic. The previous shape silently
			// dropped warnings whenever both were nil — exactly the
			// scenario the cleanupBeforeExit path triggers when
			// bootstrap aborts before the logger has been attached.
			stderr = os.Stderr
		}
		fmt.Fprintf(stderr, "Warning: %s: %v\n", msg, err)
	}
	opts := fsutil.DefaultWriteOpts()
	opts.Overwrite = true
	opts.AllowSymlink = a.Flags.AllowSymlinkOut
	f, err := fsutil.SafeCreateFile(memPath, opts)
	if err != nil {
		warnf("create memory profile", err)
		return
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			warnf("close memory profile", closeErr)
		}
	}()
	runtime.GC()
	if writeErr := pprof.WriteHeapProfile(f); writeErr != nil {
		warnf("write memory profile", writeErr)
	}
}

// checkRequireOffline validates the offline guarantee when --require-offline is set.
// It checks that no proxy environment variables are set, which would indicate the
// environment expects network connectivity that Stave does not use.
func (a *App) checkRequireOffline() error {
	if a.Flags.AllowsNetworkAccess() {
		return nil
	}
	for _, env := range kernel.DefaultPolicy().ProxyEnvVars() {
		if val := os.Getenv(env); val != "" {
			return fmt.Errorf("--require-offline: environment variable %s is set (%q); Stave makes zero network connections and proxy settings are unnecessary - unset it or remove --require-offline", env, val)
		}
	}
	return nil
}

// validateBuiltins checks integrity of embedded data (aliases, control IDs)
// at startup so errors flow through the normal exit-code path.
func (a *App) validateBuiltins() error {
	if err := predicates.ValidateAliases(); err != nil {
		return fmt.Errorf("built-in alias validation failed: %w", err)
	}
	if err := exposure.ValidateControlIDs(); err != nil {
		return fmt.Errorf("built-in control ID validation failed: %w", err)
	}
	return nil
}

// initLogger initializes the App logger based on flags.
func (a *App) initLogger() error {
	lc, err := logging.NewLogger(a.Flags.LoggingConfig())
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}

	a.bootstrapMu.Lock()
	a.LogCloser = lc
	a.Logger = lc.Logger()
	a.bootstrapMu.Unlock()
	logging.SetDefaultLogger(lc.Logger())

	return nil
}
