package cmd

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/cmdctx"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	appconfig "github.com/sufield/stave/internal/app/config"
	predicates "github.com/sufield/stave/internal/builtin/predicate"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/platform/logging"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/exposure"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

func (a *App) bootstrap(cmd *cobra.Command, _ []string) error {
	// Create cancelable root context for graceful signal handling.
	// The signal handler calls a.cancel() instead of os.Exit(),
	// allowing deferred cleanup to run.
	ctx, cancel := context.WithCancel(cmd.Context()) //nolint:gosec // cancel is stored on a.cancel and called by the signal handler
	a.cancel = cancel
	cmd.SetContext(ctx)

	if err := a.startCPUProfile(); err != nil {
		return err
	}

	// Validate built-in data integrity (aliases, control IDs) at startup
	// so errors flow through the normal exit-code path instead of panicking.
	if err := a.validateBuiltins(); err != nil {
		return err
	}

	// Build the evaluator explicitly from the filesystem. The result
	// is stored in Cobra's context — no package-level global state.
	evalResult := projconfig.BuildEvaluator()
	a.resolveGlobalFlagDefaults(cmd, evalResult.Evaluator)

	if err := a.checkRequireOffline(); err != nil {
		return err
	}
	if err := a.checkDevProductionGuard(cmd); err != nil {
		return err
	}
	if err := a.checkConfigHealth(cmd, evalResult.Err); err != nil {
		return err
	}
	ui.SetNoColor(a.Flags.NoColor)
	a.initSanitizer()
	if err := a.initLogger(); err != nil {
		return err
	}

	// Replay config-load warnings through the configured logger.
	// These were collected during BuildEvaluator before the logger
	// was initialized.
	for _, w := range evalResult.Warnings {
		a.Logger.Warn("config load warning", "error", w)
	}

	// Store the logger in Cobra's context so commands retrieve it via
	// cliflags.LoggerFromCmd(cmd) instead of reading slog.Default().
	ctx = cmdctx.WithLogger(cmd.Context(), a.Logger)
	cmd.SetContext(ctx)

	return nil
}

// resolveGlobalFlagDefaults fills global persistent flags with project-config
// defaults when the user did not set them explicitly on the command line.
// The evaluator is stored in Cobra's context so all downstream commands
// retrieve it via cmdctx.EvaluatorFromCmd(cmd).
func (a *App) resolveGlobalFlagDefaults(cmd *cobra.Command, eval *appconfig.Evaluator) {
	ctx := cmdctx.WithEvaluator(cmd.Context(), eval)
	cmd.SetContext(ctx)

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

// checkConfigHealth enforces config loading errors for commands that need config.
// Commands that can operate without a project config (init, generate, help, etc.)
// are tolerant of config failures. cfgErr is the error from BuildEvaluator().
func (a *App) checkConfigHealth(cmd *cobra.Command, cfgErr error) error {
	if cfgErr == nil {
		return nil
	}
	// Commands that work without config
	tolerant := map[string]bool{
		"init": true, "generate": true, "help": true,
		"completion": true, "doctor": true,
	}
	if tolerant[cmd.Name()] {
		return nil
	}
	return &ui.UserError{Err: fmt.Errorf(
		"project configuration is invalid: %w\n"+
			"Fix: check stave.yaml syntax or run 'stave init' to create a new one",
		cfgErr,
	)}
}

func (a *App) postRun(cmd *cobra.Command, _ []string) {
	a.stopCPUProfile()
	a.writeMemProfile(cmd)
	if a.LogCloser != nil {
		_ = a.LogCloser.Close()
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
	a.cpuProfileFile = f
	return nil
}

func (a *App) stopCPUProfile() {
	if a.cpuProfileFile == nil {
		return
	}
	pprof.StopCPUProfile()
	_ = a.cpuProfileFile.Close()
	a.cpuProfileFile = nil
}

func (a *App) writeMemProfile(cmd *cobra.Command) {
	if a.Flags.MemProfile == "" {
		return
	}
	opts := fsutil.DefaultWriteOpts()
	opts.Overwrite = true
	opts.AllowSymlink = a.Flags.AllowSymlinkOut
	f, err := fsutil.SafeCreateFile(fsutil.CleanUserPath(a.Flags.MemProfile), opts)
	if err != nil {
		if a.Logger != nil {
			a.Logger.Warn("failed to create memory profile", "error", err)
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: create memory profile: %v\n", err)
		}
		return
	}
	defer f.Close()
	runtime.GC()
	if err := pprof.WriteHeapProfile(f); err != nil {
		if a.Logger != nil {
			a.Logger.Warn("failed to write memory profile", "error", err)
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: write memory profile: %v\n", err)
		}
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
		cfg.Level = logging.ParseLevel(a.Flags.LogLevel)
	} else {
		cfg.Level = logging.LevelFromVerbosity(a.Flags.Verbosity)
	}

	cfg.Format = logging.ParseFormat(a.Flags.LogFormat)
	cfg.LogFile = fsutil.CleanUserPath(a.Flags.LogFile)
	cfg.Timestamps = a.Flags.LogTimestamps
	cfg.Timings = a.Flags.LogTimings
	cfg.AllowSymlink = a.Flags.AllowSymlinkOut
	cfg.SanitizeInfraKeys = a.Flags.Sanitize

	lc, err := logging.NewLogger(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}

	a.LogCloser = lc
	a.Logger = lc.Logger
	logging.SetDefaultLogger(lc.Logger)

	return nil
}
