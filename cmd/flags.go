package cmd

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/cli/ui"
)

// AddGlobalFlags wires persistent global flags onto the provided root command.
func AddGlobalFlags(root *cobra.Command, flags *globalFlagsType) {
	root.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return &ui.UserError{Err: ui.SuggestFlagParseError(err, cliflags.CollectVisibleFlags(cmd))}
	})

	p := root.PersistentFlags()

	// Output — zero defaults; project config resolved in PersistentPreRunE via resolveGlobalFlagDefaults.
	p.BoolVar(&flags.Quiet, cliflags.FlagQuiet, false, cliflags.WithDynamicDefaultHelp("Suppress output (exit code only)"))
	p.BoolVarP(&flags.Yes, cliflags.FlagYes, "y", false, "Auto-confirm all interactive prompts (distinct from --force which controls file overwriting)")
	p.BoolVar(&flags.NoColor, "no-color", false, "Disable ANSI colors in output")

	// Logging
	p.CountVarP(&flags.Verbosity, "verbose", "v", "Increase verbosity (-v=INFO, -vv=DEBUG)")
	p.StringVar(&flags.LogLevel, "log-level", "", "Log level: debug|info|warn|error (overrides -v)")
	p.StringVar(&flags.LogFormat, "log-format", "text", "Log format: text|json")
	p.StringVar(&flags.LogFile, cliflags.FlagLogFile, "", "Write logs to file (default: stderr)")
	p.BoolVar(&flags.LogTimestamps, "log-timestamps", false, "Include timestamps in logs (breaks determinism)")
	p.BoolVar(&flags.LogTimings, "log-timings", false, "Include timing information (breaks determinism)")

	// Safety — zero defaults; project config resolved in PersistentPreRunE via resolveGlobalFlagDefaults.
	p.BoolVar(&flags.Sanitize, cliflags.FlagSanitize, false, cliflags.WithDynamicDefaultHelp("Sanitize infrastructure identifiers (bucket names, ARNs, policies) from output"))
	p.StringVar(&flags.PathMode, cliflags.FlagPathMode, "", cliflags.WithDynamicDefaultHelp("Path rendering in errors/logs: base (basename only) or full (absolute paths)"))
	p.BoolVar(&flags.Force, cliflags.FlagForce, false, "Allow overwriting existing output files")
	p.BoolVar(&flags.AllowSymlinkOut, cliflags.FlagSymlink, false, "Allow writing output through symlinks (default: refuse)")
	p.BoolVar(&flags.RequireOffline, cliflags.FlagOffline, false, "Assert offline operation: fail if proxy env vars (HTTP_PROXY, HTTPS_PROXY, ALL_PROXY) are set")
	p.BoolVar(&flags.Strict, "strict", false, "Enable strict integrity checks for embedded registries and references")

	// Developer (hidden)
	p.StringVar(&flags.CPUProfile, "cpu-profile", "", "Write CPU profile to file")
	p.StringVar(&flags.MemProfile, "mem-profile", "", "Write heap profile to file")
	_ = p.MarkHidden("cpu-profile")
	_ = p.MarkHidden("mem-profile")
}
