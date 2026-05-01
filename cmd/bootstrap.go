package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/pprof"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/cmdctx"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	appconfig "github.com/sufield/stave/internal/app/config"
	predicates "github.com/sufield/stave/internal/builtin/predicate"
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

// phaseConfig resolves flag defaults from project/user config, env vars, and limits.
func (a *App) phaseConfig(cmd *cobra.Command) error {
	a.configResult = projconfig.BuildResolver()
	a.resolveGlobalFlagDefaults(cmd, a.configResult.Resolver)
	a.resolveEnvVarDefaults(cmd)
	a.resolveConfigurableLimits(a.configResult.Resolver)
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
	ctx := cmdctx.WithResolver(cmd.Context(), eval)
	cmd.SetContext(ctx)

	// Bootstrap can hand a nil resolver when project-config loading
	// failed and the command is annotated as config-optional.
	// Calling eval.Quiet() / Sanitize() / PathMode() on nil panics;
	// in the optional-config case the right behaviour is to fall
	// back to whatever defaults the persistent flags already carry.
	if eval == nil {
		return
	}

	p := cmd.Root().PersistentFlags()
	if !p.Changed(cliflags.FlagQuiet) {
		a.Flags.Quiet = eval.Quiet()
	}
	if !p.Changed(cliflags.FlagSanitize) {
		a.Flags.Sanitize = eval.Sanitize()
	}
	if !p.Changed(cliflags.FlagPathMode) {
		a.Flags.PathMode = eval.PathMode()
	}
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
			"Fix: check stave.yaml syntax or run 'stave init' to create a new one",
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
	a.stopCPUProfile()
	a.writeMemProfile(cmd)
	// bootstrapMu mirrors cleanupBeforeExit: phaseLogging assigns
	// LogCloser under the same mutex, and a signal handler can call
	// cleanupBeforeExit concurrently with postRun on the normal exit
	// path. Reading the pointer without the lock is a data race even
	// though Close itself is sync.Once-guarded.
	a.bootstrapMu.Lock()
	closer := a.LogCloser
	a.bootstrapMu.Unlock()
	if closer != nil {
		_ = closer.Close()
	}
}

func (a *App) startCPUProfile() error {
	if a.Flags.CPUProfile == "" {
		return nil
	}
	opts := fsutil.DefaultWriteOpts()
	opts.Overwrite = true
	opts.AllowSymlink = a.Flags.AllowSymlinkOut
	f, err := fsutil.SafeCreateFile(fsutil.CleanUserPath(a.Flags.CPUProfile), opts)
	if err != nil {
		return fmt.Errorf("create CPU profile: %w", err)
	}
	if err := pprof.StartCPUProfile(f); err != nil {
		_ = f.Close()
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
	_ = f.Close()
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
	if a.Flags.MemProfile == "" {
		return
	}
	warnf := func(msg string, err error) {
		if a.Logger != nil {
			a.Logger.Warn(msg, "error", err)
			return
		}
		if stderr != nil {
			fmt.Fprintf(stderr, "Warning: %s: %v\n", msg, err)
		}
	}
	opts := fsutil.DefaultWriteOpts()
	opts.Overwrite = true
	opts.AllowSymlink = a.Flags.AllowSymlinkOut
	f, err := fsutil.SafeCreateFile(fsutil.CleanUserPath(a.Flags.MemProfile), opts)
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
	if !a.Flags.RequireOffline {
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
	cfg := logging.DefaultConfig()

	// Determine log level
	if a.Flags.LogLevel != "" {
		cfg.Level = logging.ParseLevel(string(a.Flags.LogLevel))
	} else {
		cfg.Level = logging.LevelFromVerbosity(a.Flags.Verbosity)
	}

	cfg.Format = logging.ParseFormat(string(a.Flags.LogFormat))
	cfg.LogFile = fsutil.CleanUserPath(a.Flags.LogFile)
	cfg.Timestamps = a.Flags.LogTimestamps
	cfg.Timings = a.Flags.LogTimings
	cfg.AllowSymlink = a.Flags.AllowSymlinkOut
	cfg.SanitizeInfraKeys = a.Flags.Sanitize

	lc, err := logging.NewLogger(cfg)
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
