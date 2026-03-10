package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/platform/logging"
)

func (a *App) bootstrap(_ *cobra.Command, _ []string) error {
	if err := a.checkRequireOffline(); err != nil {
		return err
	}
	// Activate the composition owned by this App instance so that all
	// package-level convenience functions (compose.NewObservationRepository,
	// compose.NewControlRepository, etc.) delegate through App.Composition
	// rather than the package initialiser default.
	//
	// CLI commands execute sequentially, so replacing the package-level
	// variable here is safe. For parallel test isolation, use
	// compose.OverrideForTest instead.
	compose.UseComposition(a.Composition)
	return a.initLogger()
}

func (a *App) postRun(cmd *cobra.Command, _ []string) {
	if !a.Flags.Quiet && !cmdutil.IsJSONMode(a.Root) {
		fmt.Fprintln(cmd.ErrOrStderr(), "\nNeed help? Run 'stave bug-report' to create a diagnostic bundle.")
	}
	if a.LogCloser != nil {
		_ = a.LogCloser.Close()
	}
}

// checkRequireOffline validates the offline guarantee when --require-offline is set.
// It checks that no proxy environment variables are set, which would indicate the
// environment expects network connectivity that Stave does not use.
func (a *App) checkRequireOffline() error {
	if !a.Flags.RequireOffline {
		return nil
	}
	for _, env := range kernel.DefaultPolicy().ProxyEnvVars {
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
	cfg.NoColor = a.noColorRequested()

	lc, err := logging.NewLogger(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}

	a.LogCloser = lc
	a.Logger = lc.Logger
	logging.SetDefaultLogger(lc.Logger)

	return nil
}

func (a *App) noColorRequested() bool {
	if a.Flags.NoColor {
		return true
	}
	_, ok := os.LookupEnv("NO_COLOR")
	return ok
}
