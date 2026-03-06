package cmdutil

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/sufield/stave/internal/sanitize"
)

const DynamicDefaultHelpSuffix = " Resolved default may come from STAVE_* env vars, stave.yaml, user config, or built-in."

// WithDynamicDefaultHelp appends the dynamic default help suffix.
func WithDynamicDefaultHelp(help string) string {
	return help + DynamicDefaultHelpSuffix
}

// CompleteFixed returns a Cobra completion function for a fixed set of values.
func CompleteFixed(values ...string) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return values, cobra.ShellCompDirectiveNoFileComp
	}
}

// IsJSONMode returns true if the global output mode is JSON, reading from Cobra flags.
func IsJSONMode(cmd *cobra.Command) bool {
	if cmd == nil {
		return false
	}
	v, _ := cmd.Root().PersistentFlags().GetString("output")
	return v == "json"
}

// ForceEnabled returns true if the --force flag is set.
func ForceEnabled(cmd *cobra.Command) bool {
	if cmd == nil {
		return false
	}
	v, _ := cmd.Root().PersistentFlags().GetBool("force")
	return v
}

// QuietEnabled returns true if the --quiet flag is set.
func QuietEnabled(cmd *cobra.Command) bool {
	if cmd == nil {
		return false
	}
	v, _ := cmd.Root().PersistentFlags().GetBool("quiet")
	return v
}

// SanitizeEnabled returns true if --sanitize flag is set.
func SanitizeEnabled(cmd *cobra.Command) bool {
	if cmd == nil {
		return false
	}
	v, _ := cmd.Root().PersistentFlags().GetBool("sanitize")
	return v
}

// GetSanitizationPolicy returns the OutputSanitizationPolicy derived from CLI flags.
func GetSanitizationPolicy(cmd *cobra.Command) sanitize.OutputSanitizationPolicy {
	if cmd == nil {
		return sanitize.OutputSanitizationPolicy{}
	}
	sanitizeFlag := SanitizeEnabled(cmd)
	pathMode, _ := cmd.Root().PersistentFlags().GetString("path-mode")
	return sanitize.OutputSanitizationPolicy{
		SanitizeIDs: sanitizeFlag,
		PathMode:    sanitize.ParsePathMode(pathMode),
	}
}

// GetSanitizer returns the sanitizer configured by CLI flags.
func GetSanitizer(cmd *cobra.Command) *sanitize.Sanitizer {
	return GetSanitizationPolicy(cmd).Sanitizer()
}

// AllowSymlinkOutEnabled returns true if --allow-symlink-output is set.
func AllowSymlinkOutEnabled(cmd *cobra.Command) bool {
	if cmd == nil {
		return false
	}
	v, _ := cmd.Root().PersistentFlags().GetBool("allow-symlink-output")
	return v
}

// RequireOfflineEnabled returns true if --require-offline is set.
func RequireOfflineEnabled(cmd *cobra.Command) bool {
	if cmd == nil {
		return false
	}
	v, _ := cmd.Root().PersistentFlags().GetBool("require-offline")
	return v
}

// StrictEnabled returns true if --strict is set.
func StrictEnabled(cmd *cobra.Command) bool {
	if cmd == nil {
		return false
	}
	v, err := cmd.Flags().GetBool("strict")
	if err == nil {
		return v
	}
	v, _ = cmd.Root().PersistentFlags().GetBool("strict")
	return v
}

// LogFilePath returns the --log-file value.
func LogFilePath(cmd *cobra.Command) string {
	if cmd == nil {
		return ""
	}
	v, _ := cmd.Root().PersistentFlags().GetString("log-file")
	return v
}

// RegisterControlsFlag registers --controls (with -i short flag).
func RegisterControlsFlag(cmd *cobra.Command, p *string, defaultVal, usage string) {
	cmd.Flags().StringVarP(p, "controls", "i", defaultVal, usage)
}

// ControlsFlagChanged reports whether --controls was explicitly set.
func ControlsFlagChanged(cmd *cobra.Command) bool {
	return cmd.Flags().Changed("controls")
}

// ResolveFormat determines the effective output format from a flag value and
// global JSON mode. When the flag was not explicitly changed and global JSON
// mode is active, "json" is used instead.
func ResolveFormat(cmd *cobra.Command, raw string) (string, error) {
	formatRaw := strings.TrimSpace(raw)
	if cmd != nil && !cmd.Flags().Changed("format") && IsJSONMode(cmd) {
		formatRaw = "json"
	}
	return formatRaw, nil
}

// CollectVisibleFlags returns all non-hidden flag names (long and short forms)
// registered on the given command. Cobra guarantees flag name uniqueness
// within a FlagSet, so no deduplication is needed.
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
