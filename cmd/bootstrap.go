package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/initcmd"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/platform/logging"
)

func bootstrapRootCommand(_ *cobra.Command, _ []string) error {
	if err := checkRequireOffline(); err != nil {
		return err
	}
	initcmd.SetGlobals(gFlags.Force, gFlags.Quiet, gFlags.AllowSymlinkOut)
	return initLogger()
}

func postRunRootCommand(_ *cobra.Command, _ []string) {
	if !gFlags.Quiet && !IsJSONMode() {
		fmt.Fprintln(os.Stderr, "\nNeed help? Run 'stave bug-report' to create a diagnostic bundle.")
	}
	if globalLogCloser != nil {
		_ = globalLogCloser.Close()
	}
}

// checkRequireOffline validates the offline guarantee when --require-offline is set.
// It checks that no proxy environment variables are set, which would indicate the
// environment expects network connectivity that Stave does not use.
func checkRequireOffline() error {
	if !gFlags.RequireOffline {
		return nil
	}
	for _, env := range kernel.DefaultPolicy().ProxyEnvVars {
		if val := os.Getenv(env); val != "" {
			return fmt.Errorf("--require-offline: environment variable %s is set (%q); Stave makes zero network connections and proxy settings are unnecessary - unset it or remove --require-offline", env, val)
		}
	}
	return nil
}

// initLogger initializes the global logger based on flags.
func initLogger() error {
	cfg := logging.DefaultConfig()

	// Determine log level
	if gFlags.LogLevel != "" {
		cfg.Level = logging.ParseLevel(gFlags.LogLevel)
	} else {
		cfg.Level = logging.LevelFromVerbosity(gFlags.Verbosity)
	}

	cfg.Format = logging.ParseFormat(gFlags.LogFormat)
	cfg.LogFile = fsutil.CleanUserPath(gFlags.LogFile)
	cfg.Timestamps = gFlags.LogTimestamps
	cfg.Timings = gFlags.LogTimings
	cfg.AllowSymlink = gFlags.AllowSymlinkOut
	cfg.NoColor = noColorRequested()

	lc, err := logging.NewLogger(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}

	globalLogCloser = lc
	globalLogger = lc.Logger
	logging.SetDefaultLogger(lc.Logger)

	return nil
}

func noColorRequested() bool {
	if gFlags.NoColor {
		return true
	}
	_, ok := os.LookupEnv("NO_COLOR")
	return ok
}
