package cmd

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/internal/cli/ui"
)

// AddGlobalFlags wires persistent global flags onto the provided root command.
func AddGlobalFlags(root *cobra.Command, flags *globalFlagsType) {
	root.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return &ui.UserError{Err: ui.SuggestFlagParseError(err, cmdutil.CollectVisibleFlags(cmd))}
	})

	// Global persistent flags available to all commands
	flags.OutputMode = projconfig.ResolveOutputModeDefault()
	flags.Quiet = projconfig.ResolveQuietDefault()
	flags.Sanitize = projconfig.ResolveSanitizeDefault()
	flags.PathMode = projconfig.ResolvePathModeDefault()

	// Output flags
	root.PersistentFlags().StringVar(&flags.OutputMode, "output", flags.OutputMode, cmdutil.WithDynamicDefaultHelp("Output format: json or text"))
	root.PersistentFlags().BoolVar(&flags.Quiet, "quiet", flags.Quiet, cmdutil.WithDynamicDefaultHelp("Suppress output (exit code only)"))

	// Logging flags
	root.PersistentFlags().CountVarP(&flags.Verbosity, "verbose", "v", "Increase verbosity (-v=INFO, -vv=DEBUG)")
	root.PersistentFlags().StringVar(&flags.LogLevel, "log-level", "", "Log level: debug|info|warn|error (overrides -v)")
	root.PersistentFlags().StringVar(&flags.LogFormat, "log-format", "text", "Log format: text|json")
	root.PersistentFlags().StringVar(&flags.LogFile, "log-file", "", "Write logs to file (default: stderr)")
	root.PersistentFlags().BoolVar(&flags.LogTimestamps, "log-timestamps", false, "Include timestamps in logs (breaks determinism)")
	root.PersistentFlags().BoolVar(&flags.LogTimings, "log-timings", false, "Include timing information (breaks determinism)")
	root.PersistentFlags().BoolVar(&flags.Sanitize, "sanitize", flags.Sanitize, cmdutil.WithDynamicDefaultHelp("Sanitize infrastructure identifiers (bucket names, ARNs, policies) from output"))
	root.PersistentFlags().StringVar(&flags.PathMode, "path-mode", flags.PathMode, cmdutil.WithDynamicDefaultHelp("Path rendering in errors/logs: base (basename only) or full (absolute paths)"))
	root.PersistentFlags().BoolVar(&flags.Force, "force", false, "Allow overwriting existing output files")
	root.PersistentFlags().BoolVar(&flags.AllowSymlinkOut, "allow-symlink-output", false, "Allow writing output through symlinks (default: refuse)")
	root.PersistentFlags().BoolVar(&flags.RequireOffline, "require-offline", false, "Assert offline operation: fail if proxy env vars (HTTP_PROXY, HTTPS_PROXY, ALL_PROXY) are set")
	root.PersistentFlags().BoolVar(&flags.Strict, "strict", false, "Enable strict integrity checks for embedded registries and references")
	root.PersistentFlags().BoolVar(&flags.NoColor, "no-color", false, "Disable ANSI colors in output")

	// Performance profiling flags (hidden — for developer use only)
	root.PersistentFlags().StringVar(&flags.CPUProfile, "cpu-profile", "", "Write CPU profile to file")
	root.PersistentFlags().StringVar(&flags.MemProfile, "mem-profile", "", "Write heap profile to file")
	_ = root.PersistentFlags().MarkHidden("cpu-profile")
	_ = root.PersistentFlags().MarkHidden("mem-profile")
}
