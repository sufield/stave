package cmdutil

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/sufield/stave/internal/sanitize"
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
	FlagControls      = "controls"
	FlagControlsShort = "i"
)

const DynamicDefaultHelpSuffix = " Resolved default may come from STAVE_* env vars, stave.yaml, user config, or built-in."

// GlobalFlags represents the state of persistent flags registered at the root.
type GlobalFlags struct {
	Quiet             bool
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

// --- Internal Utilities ---

// Best-effort: pflag always returns a usable zero value; the error is vestigial
// (only fires for type mismatch or unregistered flag, both caught by Cobra).
func getStr(fs *pflag.FlagSet, name string) string {
	val, _ := fs.GetString(name)
	return val
}

// Best-effort: pflag always returns a usable zero value; the error is vestigial.
func getBool(fs *pflag.FlagSet, name string) bool {
	val, _ := fs.GetBool(name)
	return val
}
