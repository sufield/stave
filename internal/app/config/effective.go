package config

import (
	"path/filepath"

	"github.com/sufield/stave/internal/core/retention"
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
	ConfigFile               string                    `json:"config_file,omitempty"`
	UserConfigFile           string                    `json:"user_config_file,omitempty"`
	ProjectRoot              string                    `json:"project_root,omitempty"`
	MaxUnsafeDuration        ResolvedField             `json:"max_unsafe"`
	SnapshotRetention        ResolvedField             `json:"snapshot_retention"`
	DefaultRetentionTier     ResolvedField             `json:"default_retention_tier"`
	CIFailurePolicy          ResolvedField             `json:"ci_failure_policy"`
	CLIOutput                ResolvedField             `json:"cli_output"`
	CLIQuiet                 ResolvedField             `json:"cli_quiet"`
	CLISanitize              ResolvedField             `json:"cli_sanitize"`
	CLIPathMode              ResolvedField             `json:"cli_path_mode"`
	CLIAllowUnknownInput     ResolvedField             `json:"cli_allow_unknown_input"`
	DefinedRetentionTiers    map[string]retention.Tier `json:"defined_retention_tiers"`
	EffectiveRetentionByTier map[string]ResolvedField  `json:"effective_retention_by_tier"`
}

// toResolvedField converts a PolicyValue[T] to a ResolvedField.
func toResolvedField[T any](v PolicyValue[T]) ResolvedField {
	return ResolvedField{Value: v.String(), Source: v.Source}
}

// BuildEffectiveConfig assembles the fully resolved configuration with provenance,
// suitable for `stave config show` output.
func (e *GovernanceResolver) BuildEffectiveConfig() EffectiveConfig {
	retTier := e.ResolveRetentionTier()
	out := EffectiveConfig{
		DefaultRetentionTier:     toResolvedField(retTier),
		MaxUnsafeDuration:        toResolvedField(e.ResolveMaxUnsafeDuration()),
		SnapshotRetention:        toResolvedField(e.ResolveSnapshotRetention(retTier.Value)),
		CIFailurePolicy:          toResolvedField(e.ResolveCIFailurePolicy()),
		CLIOutput:                toResolvedField(e.ResolveCLIOutput()),
		CLIQuiet:                 toResolvedField(e.ResolveCLIQuiet()),
		CLISanitize:              toResolvedField(e.ResolveCLISanitize()),
		CLIPathMode:              toResolvedField(e.ResolveCLIPathMode()),
		CLIAllowUnknownInput:     toResolvedField(e.ResolveCLIAllowUnknownInput()),
		DefinedRetentionTiers:    e.buildDefinedRetentionTiers(),
		EffectiveRetentionByTier: map[string]ResolvedField{},
	}
	if e.PolicyPath != "" {
		out.ConfigFile = e.PolicyPath
		out.ProjectRoot = filepath.Dir(e.PolicyPath)
	}
	if e.SettingsPath != "" {
		out.UserConfigFile = e.SettingsPath
	}
	for tier := range out.DefinedRetentionTiers {
		out.EffectiveRetentionByTier[tier] = toResolvedField(e.ResolveSnapshotRetention(tier))
	}
	return out
}

func (e *GovernanceResolver) buildDefinedRetentionTiers() map[string]retention.Tier {
	if e.Policy != nil {
		if tiers := ResolveDefinedRetentionTiers(e.Policy); len(tiers) > 0 {
			return tiers
		}
	}
	return map[string]retention.Tier{
		DefaultRetentionTier: {OlderThan: DefaultSnapshotRetention, KeepMin: DefaultTierKeepMin},
	}
}
