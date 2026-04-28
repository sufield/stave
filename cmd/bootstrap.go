package cmd

import (
	"context"
	"fmt"
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
