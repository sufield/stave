package cmdutil

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/sufield/stave/internal/sanitize"
)

// Flag constants to prevent typos across the CLI tree.
const (
	FlagOutput        = "output"
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
	Output            string
	Quiet             bool
	Force             bool
	Sanitize          bool
	PathMode          string
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
		Output:          getStr(rootFlags, FlagOutput),
		Quiet:           getBool(rootFlags, FlagQuiet),
		Force:           getBool(rootFlags, FlagForce),
		Sanitize:        getBool(rootFlags, FlagSanitize),
		PathMode:        getStr(rootFlags, FlagPathMode),
		Strict:          getBool(rootFlags, FlagStrict),
		LogFile:         getStr(rootFlags, FlagLogFile),
		RequireOffline:  getBool(rootFlags, FlagOffline),
		AllowSymlinkOut: getBool(rootFlags, FlagSymlink),
	}
}

// --- Logic Helpers (Decoupled from Cobra) ---

// IsJSONMode returns true if the output mode is set to JSON.
func (g GlobalFlags) IsJSONMode() bool {
	return g.Output == "json"
}

// TextOutputEnabled returns true if human-readable text should be printed.
func (g GlobalFlags) TextOutputEnabled() bool {
	return !g.Quiet && !g.IsJSONMode()
}

// GetSanitizer returns a configured sanitizer based on the global flags.
func (g GlobalFlags) GetSanitizer() *sanitize.Sanitizer {
	policy := sanitize.OutputSanitizationPolicy{
		SanitizeIDs: g.Sanitize,
		PathMode:    ParsePathMode(g.PathMode),
	}
	return policy.Sanitizer()
}

// ParsePathMode parses a CLI flag string to a sanitize.PathMode, defaulting to PathModeBase.
func ParsePathMode(s string) sanitize.PathMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case string(sanitize.PathModeFull):
		return sanitize.PathModeFull
	default:
		return sanitize.PathModeBase
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

// ResolveFormat calculates the effective output format, accounting for JSON mode overrides.
func ResolveFormat(cmd *cobra.Command, rawFormat string) string {
	if cmd == nil {
		return rawFormat
	}
	if !cmd.Flags().Changed(FlagFormat) && GetGlobalFlags(cmd).IsJSONMode() {
		return "json"
	}
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

func getStr(fs *pflag.FlagSet, name string) string {
	val, _ := fs.GetString(name)
	return val
}

func getBool(fs *pflag.FlagSet, name string) bool {
	val, _ := fs.GetBool(name)
	return val
}
