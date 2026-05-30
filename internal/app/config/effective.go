package config

import (
	"path/filepath"
)

// ResolvedField pairs a configuration value with its originating source
// (e.g., environment variable, file path, or hardcoded default).
type ResolvedField struct {
	Value  string `json:"value"`
	Source string `json:"source"`
}

// EffectiveConfig represents the fully resolved, merged configuration state
// as seen by the CLI.
type EffectiveConfig struct {
	ConfigFile        string        `json:"config_file,omitempty"`
	UserConfigFile    string        `json:"user_config_file,omitempty"`
	ProjectRoot       string        `json:"project_root,omitempty"`
	MaxUnsafeDuration ResolvedField `json:"max_unsafe"`
	CIFailurePolicy   ResolvedField `json:"ci_failure_policy"`
	CLIOutput         ResolvedField `json:"cli_output"`
	CLIQuiet          ResolvedField `json:"cli_quiet"`
	CLISanitize       ResolvedField `json:"cli_sanitize"`
	CLIPathMode       ResolvedField `json:"cli_path_mode"`
}

// toResolvedField converts a PolicyValue[T] to a ResolvedField.
func toResolvedField[T any](v PolicyValue[T]) ResolvedField {
	return ResolvedField{Value: v.String(), Source: v.Source}
}

// BuildEffectiveConfig assembles the fully resolved configuration with provenance,
// suitable for `stave config show` output.
func (e *GovernanceResolver) BuildEffectiveConfig() EffectiveConfig {
	out := EffectiveConfig{
		MaxUnsafeDuration: toResolvedField(e.ResolveMaxUnsafeDuration()),
		CIFailurePolicy:   toResolvedField(e.ResolveCIFailurePolicy()),
		CLIOutput:         toResolvedField(e.ResolveCLIOutput()),
		CLIQuiet:          toResolvedField(e.ResolveCLIQuiet()),
		CLISanitize:       toResolvedField(e.ResolveCLISanitize()),
		CLIPathMode:       toResolvedField(e.ResolveCLIPathMode()),
	}
	if e.PolicyPath != "" {
		out.ConfigFile = e.PolicyPath
		out.ProjectRoot = filepath.Dir(e.PolicyPath)
	}
	if e.SettingsPath != "" {
		out.UserConfigFile = e.SettingsPath
	}
	return out
}
