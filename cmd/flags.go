package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

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
	p.Var(&flags.LogLevel, "log-level", "Log level: debug|info|warn|error (overrides -v)")
	// Seed LogFormat through the pflag.Value contract by registering
	// then calling Set("text"). Direct field assignment side-stepped
	// pflag's bookkeeping — the value was set but pflag did not mark
	// the flag as defaulted, so resolveGlobalFlagDefaults could not
	// distinguish "user passed --log-format=text" from "default
	// applied" via p.Changed(). The Set route updates both.
	p.Var(&flags.LogFormat, "log-format", "Log format: text|json")
	if err := p.Lookup("log-format").Value.Set("text"); err != nil {
		// pflag only errors here when the Value.Set implementation
		// rejects the string. logging.Format.Set always returns nil,
		// so this is a structural test-time check: if a future
		// Format.Set adds validation, fail loud at startup.
		panic("flags: failed to seed log-format default: " + err.Error())
	}
	p.Lookup("log-format").DefValue = "text"
	p.Lookup("log-format").Changed = false
	p.StringVar(&flags.LogFile, cliflags.FlagLogFile, "", "Write logs to file (default: stderr)")
	p.BoolVar(&flags.LogTimestamps, "log-timestamps", false, "Include timestamps in logs (breaks determinism)")
	p.BoolVar(&flags.LogTimings, "log-timings", false, "Include timing information (breaks determinism)")

	// Safety — zero defaults; project config resolved in PersistentPreRunE via resolveGlobalFlagDefaults.
	p.BoolVar(&flags.Sanitize, cliflags.FlagSanitize, false, cliflags.WithDynamicDefaultHelp("Sanitize infrastructure identifiers (bucket names, ARNs, policies) from output"))
	p.Var(&flags.PathMode, cliflags.FlagPathMode, cliflags.WithDynamicDefaultHelp("Path rendering in errors/logs: base (basename only) or full (absolute paths)"))
	p.BoolVar(&flags.Force, cliflags.FlagForce, false, "Allow overwriting existing output files")
	p.BoolVar(&flags.AllowSymlinkOut, cliflags.FlagSymlink, false, "Allow writing output through symlinks (default: refuse)")
	p.BoolVar(&flags.RequireOffline, cliflags.FlagOffline, false, "Assert offline operation: fail if proxy env vars (HTTP_PROXY, HTTPS_PROXY, ALL_PROXY) are set")
	p.BoolVar(&flags.Strict, "strict", false, "Enable strict integrity checks for embedded registries and references")

	// Developer (hidden). MarkHidden returns an error only when the
	// named flag does not exist on the FlagSet — a programming-time
	// invariant under our control, not a runtime condition. The
	// blank-identifier discards papered over a bug where a typo in
	// the flag name silently failed to hide the flag from --help;
	// mustHide panics with the offending name so the developer sees
	// the typo at startup.
	p.StringVar(&flags.CPUProfile, "cpu-profile", "", "Write CPU profile to file")
	p.StringVar(&flags.MemProfile, "mem-profile", "", "Write heap profile to file")
	mustHide(p, "cpu-profile")
	mustHide(p, "mem-profile")
}

func mustHide(fs *pflag.FlagSet, name string) {
	if err := fs.MarkHidden(name); err != nil {
		panic(fmt.Sprintf("cmd.mustHide: flag %q: %v", name, err))
	}
}
