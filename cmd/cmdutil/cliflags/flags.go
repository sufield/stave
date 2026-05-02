// Package cliflags provides CLI flag constants, global flag extraction,
// sanitizer construction, completion helpers, and flag parsing utilities.
package cliflags

import (
	"fmt"
	"log/slog"
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

// DynamicDefaultHelpSuffix is appended to flag help text when the default
// value may be resolved from environment variables, project config, or user config.
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

// ParsePathMode parses a CLI flag string to a sanitize.PathMode,
// defaulting to PathBase. Unrecognised values log a warning and fall
// back to PathBase so the operator sees the misuse instead of
// silently getting a different mode than they asked for.
//
// sanitize.PathBase is the empty string by design (it's the
// "default" mode), so the "" case is part of the legitimate input
// set rather than a synthetic alias — it does not warn.
func ParsePathMode(s string) sanitize.PathMode {
	normalized := strings.ToLower(strings.TrimSpace(s))
	switch normalized {
	case string(sanitize.PathBase): // "" — default
		return sanitize.PathBase
	case string(sanitize.PathFull):
		return sanitize.PathFull
	case "base": // explicit alias for the default
		return sanitize.PathBase
	default:
		slog.Warn("cliflags: unrecognised PathMode value, defaulting to base",
			"value", s, "expected", []string{string(sanitize.PathBase), string(sanitize.PathFull)})
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

// FlagName identifies a CLI flag for error-wrapping. Typed so the
// (value, flag-name) pair on parsers like ParseDurationFlag and
// ParseRFC3339 cannot be transposed at the call site — both the
// raw value and the flag name are short, opaque strings, and the
// previous (val, flag string) signature made the swap silently
// compile.
type FlagName string

// ParseDurationFlag parses a duration flag value and wraps errors with the flag name.
func ParseDurationFlag(val string, flag FlagName) (time.Duration, error) {
	d, err := kernel.ParseDuration(val)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q (use format: 168h, 7d, or 1d12h)", flag, val)
	}
	return d, nil
}

// ParseRFC3339 parses an RFC3339 timestamp with a flag-name error message.
func ParseRFC3339(raw string, flag FlagName) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid %s %q (use RFC3339: 2026-01-15T00:00:00Z)", flag, raw)
	}
	return t.UTC(), nil
}

// --- Internal Utilities ---

// getStr / getBool fetch a flag's typed value when it is known to
// exist. Lookup-then-Get is split because the calling pattern is
// "tolerate flag absence" (Lookup nil → empty default) but treat a
// type mismatch as a programming-time invariant violation: the flag
// was registered with a different type than the caller is asking
// for, which is a developer mistake that pflag cannot recover from.
//
// Earlier shape logged the type-mismatch error at slog.Error and
// returned the zero value, which silently produced incorrect
// behaviour at every downstream call site (e.g. a bool flag that
// looked like "false" because it was registered as a string).
// Panic surfaces the bug at the exact call site instead.
func getStr(fs *pflag.FlagSet, name string) string {
	if fs.Lookup(name) == nil {
		return ""
	}
	val, err := fs.GetString(name)
	if err != nil {
		panic(fmt.Sprintf("cliflags: flag %q is registered but not a string: %v", name, err))
	}
	return val
}

func getBool(fs *pflag.FlagSet, name string) bool {
	if fs.Lookup(name) == nil {
		return false
	}
	val, err := fs.GetBool(name)
	if err != nil {
		panic(fmt.Sprintf("cliflags: flag %q is registered but not a bool: %v", name, err))
	}
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

// AllThresholdStatuses returns all valid risk threshold status labels for CLI completion.
func AllThresholdStatuses() []string {
	return []string{"OVERDUE", "DUE_NOW", "UPCOMING"}
}

// DefaultControlsDir is the conventional default path for control definitions.
// Used as the flag default across all commands that accept --controls.
const DefaultControlsDir = "controls"
