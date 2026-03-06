package cmd

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/cli/ui"
)

func init() {
	AddGlobalFlags(RootCmd)
}

// AddGlobalFlags wires persistent global flags onto the provided root command.
func AddGlobalFlags(root *cobra.Command) {
	root.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return ui.SuggestFlagParseError(err, cmdutil.CollectVisibleFlags(cmd))
	})

	// Global persistent flags available to all commands
	gFlags.OutputMode = cmdutil.ResolveOutputModeDefault()
	gFlags.Quiet = cmdutil.ResolveQuietDefault()
	gFlags.Sanitize = cmdutil.ResolveSanitizeDefault()
	gFlags.PathMode = cmdutil.ResolvePathModeDefault()

	// Output flags
	root.PersistentFlags().StringVar(&gFlags.OutputMode, "output", gFlags.OutputMode, cmdutil.WithDynamicDefaultHelp("Output format: json or text"))
	root.PersistentFlags().BoolVar(&gFlags.Quiet, "quiet", gFlags.Quiet, cmdutil.WithDynamicDefaultHelp("Suppress output (exit code only)"))

	// Logging flags
	root.PersistentFlags().CountVarP(&gFlags.Verbosity, "verbose", "v", "Increase verbosity (-v=INFO, -vv=DEBUG)")
	root.PersistentFlags().StringVar(&gFlags.LogLevel, "log-level", "", "Log level: debug|info|warn|error (overrides -v)")
	root.PersistentFlags().StringVar(&gFlags.LogFormat, "log-format", "text", "Log format: text|json")
	root.PersistentFlags().StringVar(&gFlags.LogFile, "log-file", "", "Write logs to file (default: stderr)")
	root.PersistentFlags().BoolVar(&gFlags.LogTimestamps, "log-timestamps", false, "Include timestamps in logs (breaks determinism)")
	root.PersistentFlags().BoolVar(&gFlags.LogTimings, "log-timings", false, "Include timing information (breaks determinism)")
	root.PersistentFlags().BoolVar(&gFlags.Sanitize, "sanitize", gFlags.Sanitize, cmdutil.WithDynamicDefaultHelp("Sanitize infrastructure identifiers (bucket names, ARNs, policies) from output"))
	root.PersistentFlags().StringVar(&gFlags.PathMode, "path-mode", gFlags.PathMode, cmdutil.WithDynamicDefaultHelp("Path rendering in errors/logs: base (basename only) or full (absolute paths)"))
	root.PersistentFlags().BoolVar(&gFlags.Force, "force", false, "Allow overwriting existing output files")
	root.PersistentFlags().BoolVar(&gFlags.AllowSymlinkOut, "allow-symlink-output", false, "Allow writing output through symlinks (default: refuse)")
	root.PersistentFlags().BoolVar(&gFlags.RequireOffline, "require-offline", false, "Assert offline operation: fail if proxy env vars (HTTP_PROXY, HTTPS_PROXY, ALL_PROXY) are set")
	root.PersistentFlags().BoolVar(&gFlags.Strict, "strict", false, "Enable strict integrity checks for embedded registries and references")
	root.PersistentFlags().BoolVar(&gFlags.NoColor, "no-color", false, "Disable ANSI colors in output")
}
