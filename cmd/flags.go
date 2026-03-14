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

	// Resolve dynamic defaults from project/user configuration.
	eval := projconfig.Global()
	flags.OutputMode = eval.OutputMode()
	flags.Quiet = eval.Quiet()
	flags.Sanitize = eval.Sanitize()
	flags.PathMode = eval.PathMode()

	p := root.PersistentFlags()

	// Output
	p.StringVar(&flags.OutputMode, cmdutil.FlagOutput, flags.OutputMode, cmdutil.WithDynamicDefaultHelp("Output format: json or text"))
	p.BoolVar(&flags.Quiet, cmdutil.FlagQuiet, flags.Quiet, cmdutil.WithDynamicDefaultHelp("Suppress output (exit code only)"))
	p.BoolVar(&flags.NoColor, "no-color", false, "Disable ANSI colors in output")

	// Logging
	p.CountVarP(&flags.Verbosity, "verbose", "v", "Increase verbosity (-v=INFO, -vv=DEBUG)")
	p.StringVar(&flags.LogLevel, "log-level", "", "Log level: debug|info|warn|error (overrides -v)")
	p.StringVar(&flags.LogFormat, "log-format", "text", "Log format: text|json")
	p.StringVar(&flags.LogFile, cmdutil.FlagLogFile, "", "Write logs to file (default: stderr)")
	p.BoolVar(&flags.LogTimestamps, "log-timestamps", false, "Include timestamps in logs (breaks determinism)")
	p.BoolVar(&flags.LogTimings, "log-timings", false, "Include timing information (breaks determinism)")

	// Safety
	p.BoolVar(&flags.Sanitize, cmdutil.FlagSanitize, flags.Sanitize, cmdutil.WithDynamicDefaultHelp("Sanitize infrastructure identifiers (bucket names, ARNs, policies) from output"))
	p.StringVar(&flags.PathMode, cmdutil.FlagPathMode, flags.PathMode, cmdutil.WithDynamicDefaultHelp("Path rendering in errors/logs: base (basename only) or full (absolute paths)"))
	p.BoolVar(&flags.Force, cmdutil.FlagForce, false, "Allow overwriting existing output files")
	p.BoolVar(&flags.AllowSymlinkOut, cmdutil.FlagSymlink, false, "Allow writing output through symlinks (default: refuse)")
	p.BoolVar(&flags.RequireOffline, cmdutil.FlagOffline, false, "Assert offline operation: fail if proxy env vars (HTTP_PROXY, HTTPS_PROXY, ALL_PROXY) are set")
	p.BoolVar(&flags.Strict, "strict", false, "Enable strict integrity checks for embedded registries and references")

	// Developer (hidden)
	p.StringVar(&flags.CPUProfile, "cpu-profile", "", "Write CPU profile to file")
	p.StringVar(&flags.MemProfile, "mem-profile", "", "Write heap profile to file")
	_ = p.MarkHidden("cpu-profile")
	_ = p.MarkHidden("mem-profile")
}
