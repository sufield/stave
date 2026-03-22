package cmd

import (
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/cmdctx"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/platform/logging"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

func (a *App) bootstrap(cmd *cobra.Command, _ []string) error {
	if err := a.startCPUProfile(); err != nil {
		return err
	}
	a.resolveGlobalFlagDefaults(cmd)
	if err := a.validateOutputMode(); err != nil {
		return err
	}
	if err := a.checkRequireOffline(); err != nil {
		return err
	}
	if err := a.checkDevProductionGuard(cmd); err != nil {
		return err
	}
	if err := a.checkConfigHealth(cmd); err != nil {
		return err
	}
	ui.SetNoColor(a.Flags.NoColor)
	a.initSanitizer()
	if err := a.initLogger(); err != nil {
		return err
	}

	// Store the logger in Cobra's context so commands retrieve it via
	// cmdutil.LoggerFromCmd(cmd) instead of reading slog.Default().
	ctx := cmdctx.WithLogger(cmd.Context(), a.Logger)
	cmd.SetContext(ctx)

	return nil
}

// resolveGlobalFlagDefaults fills global persistent flags with project-config
// defaults when the user did not set them explicitly on the command line.
func (a *App) resolveGlobalFlagDefaults(cmd *cobra.Command) {
	// Boundary: this is the single production call site for projconfig.Global().
	// The evaluator is resolved here and stored in Cobra's context so all
	// downstream commands retrieve it via cmdutil.EvaluatorFromCmd(cmd).
	eval := projconfig.Global()
	ctx := cmdctx.WithEvaluator(cmd.Context(), eval)
	cmd.SetContext(ctx)

	p := cmd.Root().PersistentFlags()
	if !p.Changed(cmdutil.FlagOutput) {
		a.Flags.OutputMode = eval.OutputMode()
	}
	if !p.Changed(cmdutil.FlagQuiet) {
		a.Flags.Quiet = eval.Quiet()
	}
	if !p.Changed(cmdutil.FlagSanitize) {
		a.Flags.Sanitize = eval.Sanitize()
	}
	if !p.Changed(cmdutil.FlagPathMode) {
		a.Flags.PathMode = eval.PathMode()
	}
}

// checkConfigHealth enforces config loading errors for commands that need config.
// Commands that can operate without a project config (init, generate, help, etc.)
// are tolerant of config failures.
func (a *App) checkConfigHealth(cmd *cobra.Command) error {
	cfgErr := projconfig.GlobalConfigError()
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
	if !a.Flags.Quiet && !cmdutil.GetGlobalFlags(a.Root).IsJSONMode() {
		fmt.Fprintln(cmd.ErrOrStderr(), "\nNeed help? Run 'stave bug-report' to create a diagnostic bundle.")
	}
	if a.LogCloser != nil {
		_ = a.LogCloser.Close()
	}
}

func (a *App) startCPUProfile() error {
	if a.Flags.CPUProfile == "" {
		return nil
	}
	f, err := os.Create(fsutil.CleanUserPath(a.Flags.CPUProfile))
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
	f, err := os.Create(fsutil.CleanUserPath(a.Flags.MemProfile))
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Warning: create memory profile: %v\n", err)
		return
	}
	defer f.Close()
	runtime.GC()
	if err := pprof.WriteHeapProfile(f); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Warning: write memory profile: %v\n", err)
	}
}

// validateOutputMode validates the --output flag value early, before any command runs.
func (a *App) validateOutputMode() error {
	_, err := ui.ParseOutputMode(a.Flags.OutputMode)
	return err
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

	lc, err := logging.NewLogger(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}

	a.LogCloser = lc
	a.Logger = lc.Logger
	logging.SetDefaultLogger(lc.Logger)

	return nil
}
