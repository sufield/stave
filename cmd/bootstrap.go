package cmd

import (
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/platform/logging"
)

func (a *App) bootstrap(cmd *cobra.Command, _ []string) error {
	if err := a.startCPUProfile(); err != nil {
		return err
	}
	if err := a.validateOutputMode(); err != nil {
		return err
	}
	if err := a.checkRequireOffline(); err != nil {
		return err
	}
	if err := a.checkDevProductionGuard(cmd); err != nil {
		return err
	}
	a.initSanitizer()
	return a.initLogger()
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
