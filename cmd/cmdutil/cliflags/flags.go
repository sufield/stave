// Package cliflags provides CLI flag constants, global flag extraction,
// sanitizer construction, completion helpers, and flag parsing utilities.
package cliflags

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/env"
	"github.com/sufield/stave/internal/sanitize"
)

// Standard format completion sets derived from contracts.OutputFormat constants.
var (
	// FormatsTextJSON covers commands that support text and JSON output.
	FormatsTextJSON = []string{string(contracts.FormatText), string(contracts.FormatJSON)}
	// FormatsTextJSONSARIF covers commands that also support SARIF output.
	FormatsTextJSONSARIF = []string{string(contracts.FormatJSON), string(contracts.FormatText), string(contracts.FormatSARIF)}
	// FormatsMarkdownJSON covers commands that support markdown and JSON output.
	FormatsMarkdownJSON = []string{string(contracts.FormatMarkdown), string(contracts.FormatJSON)}
)

// Flag constants to prevent typos across the CLI tree.
const (
	FlagFormat        = "format"
	FlagQuiet         = "quiet"
	FlagForce         = "force"
	FlagSanitize      = "sanitize"
	FlagPathMode      = "path-mode"
	FlagStrict        = "strict"
	FlagLogFile       = "log-file"
	FlagOffline       = "require-offline"
	FlagSymlink       = "allow-symlink-output"
	FlagYes           = "yes"
	FlagControls      = "controls"
	FlagControlsShort = "i"
)

const DynamicDefaultHelpSuffix = " Resolved default may come from STAVE_* env vars, stave.yaml, user config, or built-in."

// GlobalFlags represents the state of persistent flags registered at the root.
type GlobalFlags struct {
	Quiet             bool
	Yes               bool
	Force             bool
	Sanitize          bool
	PathMode          sanitize.PathMode
	Strict            bool
	LogFile           string
	RequireOffline    bool
	AllowSymlinkOut   bool
	AllowUnknownInput bool
}

// GetGlobalFlags extracts the root persistent flags into a typed struct.
// This should be called once at the start of a command's RunE.
func GetGlobalFlags(cmd *cobra.Command) GlobalFlags {
	if cmd == nil {
		return GlobalFlags{}
	}
	rootFlags := cmd.Root().PersistentFlags()

	return GlobalFlags{
		Quiet:           getBool(rootFlags, FlagQuiet),
		Yes:             getBool(rootFlags, FlagYes),
		Force:           getBool(rootFlags, FlagForce),
		Sanitize:        getBool(rootFlags, FlagSanitize),
		PathMode:        ParsePathMode(getStr(rootFlags, FlagPathMode)),
		Strict:          getBool(rootFlags, FlagStrict),
		LogFile:         getStr(rootFlags, FlagLogFile),
		RequireOffline:  getBool(rootFlags, FlagOffline),
		AllowSymlinkOut: getBool(rootFlags, FlagSymlink),
	}
}

// --- Logic Helpers (Decoupled from Cobra) ---

// TextOutputEnabled returns true if human-readable text should be printed.
func (g GlobalFlags) TextOutputEnabled() bool {
	return !g.Quiet
}

// AutoConfirm returns true when interactive prompts should be auto-confirmed.
// This is true when --yes is set or when stderr is not a TTY (non-interactive).
func (g GlobalFlags) AutoConfirm() bool {
	return g.Yes
}

// GetSanitizer returns a configured sanitizer based on the global flags.
func (g GlobalFlags) GetSanitizer() *sanitize.Sanitizer {
	policy := sanitize.Policy{
		SanitizeIDs: g.Sanitize,
		PathMode:    g.PathMode,
	}
	return policy.NewSanitizer()
}

// ParsePathMode parses a CLI flag string to a sanitize.PathMode, defaulting to PathBase.
func ParsePathMode(s string) sanitize.PathMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case string(sanitize.PathFull):
		return sanitize.PathFull
	default:
		return sanitize.PathBase
	}
}

// --- Cobra Specific Helpers ---

// WithDynamicDefaultHelp appends the dynamic default help suffix to a usage string.
func WithDynamicDefaultHelp(help string) string {
	return help + DynamicDefaultHelpSuffix
}

// CompleteFixed returns a Cobra completion function for a fixed set of values.
func CompleteFixed(values ...string) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return values, cobra.ShellCompDirectiveNoFileComp
	}
}

// RegisterControlsFlag adds the standard --controls (-i) flag to a command.
func RegisterControlsFlag(cmd *cobra.Command, p *string, defaultVal, usage string) {
	cmd.Flags().StringVarP(p, FlagControls, FlagControlsShort, defaultVal, usage)
}

// ControlsFlagChanged reports whether --controls was explicitly set.
func ControlsFlagChanged(cmd *cobra.Command) bool {
	return cmd.Flags().Changed(FlagControls)
}

// ResolveFormat returns the trimmed format string.
func ResolveFormat(_ *cobra.Command, rawFormat string) string {
	return strings.TrimSpace(rawFormat)
}

// ResolveFormatPure returns the trimmed format string without cobra.
func ResolveFormatPure(rawFormat string, _ bool, _ bool) string {
	return strings.TrimSpace(rawFormat)
}

// CollectVisibleFlags returns a list of all non-hidden flag strings (e.g., "--force", "-f").
func CollectVisibleFlags(cmd *cobra.Command) []string {
	var flags []string
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if f.Hidden {
			return
		}
		flags = append(flags, "--"+f.Name)
		if f.Shorthand != "" {
			flags = append(flags, "-"+f.Shorthand)
		}
	})
	return flags
}

// --- Parsing Helpers ---

// ParseDurationFlag parses a duration flag value and wraps errors with the flag name.
func ParseDurationFlag(val, flag string) (time.Duration, error) {
	d, err := kernel.ParseDuration(val)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q (use format: 168h, 7d, or 1d12h)", flag, val)
	}
	return d, nil
}

// ParseRFC3339 parses an RFC3339 timestamp with a flag-name error message.
func ParseRFC3339(raw, flag string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid %s %q (use RFC3339: 2026-01-15T00:00:00Z)", flag, raw)
	}
	return t.UTC(), nil
}

// --- Internal Utilities ---

func getStr(fs *pflag.FlagSet, name string) string {
	val, _ := fs.GetString(name)
	return val
}

func getBool(fs *pflag.FlagSet, name string) bool {
	val, _ := fs.GetBool(name)
	return val
}

// --- Environment Variable Resolution ---
//
// These helpers resolve per-command flags from STAVE_* env vars when the flag
// was not explicitly set on the command line.
// Precedence: CLI flag > env var > config file > default.

// ResolveFormatEnv returns the env-var override for --format if the flag was
// not explicitly set by the user. Returns the original value if no override applies.
func ResolveFormatEnv(cmd *cobra.Command, current string) string {
	if cmd.Flags().Changed(FlagFormat) {
		return current
	}
	if v := env.Format.Value(); v != "" {
		return v
	}
	return current
}

// ResolveControlsEnv returns the env-var override for --controls if the flag was
// not explicitly set by the user. Returns the original value if no override applies.
func ResolveControlsEnv(cmd *cobra.Command, current string) string {
	if cmd.Flags().Changed(FlagControls) {
		return current
	}
	if v := env.Controls.Value(); v != "" {
		return v
	}
	return current
}

// ResolveObservationsEnv returns the env-var override for --observations if the
// flag was not explicitly set by the user. Returns the original value if no
// override applies.
func ResolveObservationsEnv(cmd *cobra.Command, current string) string {
	if !cmd.Flags().Changed("observations") {
		if v := env.Observations.Value(); v != "" {
			return v
		}
	}
	return current
}

// ResolveNowEnv returns the env-var override for --now if the flag was not
// explicitly set by the user. Returns the original value if no override applies.
func ResolveNowEnv(cmd *cobra.Command, current string) string {
	if !cmd.Flags().Changed("now") {
		if v := env.Now.Value(); v != "" {
			return v
		}
	}
	return current
}
