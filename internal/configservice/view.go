package configservice

import (
	"sort"
)

// ResolvedField is a value annotated with its source.
type ResolvedField struct {
	Value  string `json:"value"`
	Source string `json:"source"`
}

// EffectiveConfig is the CLI-facing shape of resolved config values.
type EffectiveConfig struct {
	ConfigFile               string                         `json:"config_file,omitempty"`
	UserConfigFile           string                         `json:"user_config_file,omitempty"`
	ProjectRoot              string                         `json:"project_root,omitempty"`
	MaxUnsafe                ResolvedField                  `json:"max_unsafe"`
	SnapshotRetention        ResolvedField                  `json:"snapshot_retention"`
	DefaultRetentionTier     ResolvedField                  `json:"default_retention_tier"`
	CIFailurePolicy          ResolvedField                  `json:"ci_failure_policy"`
	CLIOutput                ResolvedField                  `json:"cli_output"`
	CLIQuiet                 ResolvedField                  `json:"cli_quiet"`
	CLISanitize              ResolvedField                  `json:"cli_sanitize"`
	CLIPathMode              ResolvedField                  `json:"cli_path_mode"`
	CLIAllowUnknownInput     ResolvedField                  `json:"cli_allow_unknown_input"`
	DefinedRetentionTiers    map[string]RetentionTierConfig `json:"defined_retention_tiers"`
	EffectiveRetentionByTier map[string]ResolvedField       `json:"effective_retention_by_tier"`
}

// BuildKeyCompletions builds stable config key completions including tier paths.
func BuildKeyCompletions(baseKeys []string, tiers []string) []string {
	keys := make([]string, 0, len(baseKeys)+len(tiers)*3)
	keys = append(keys, baseKeys...)

	seen := make(map[string]struct{}, len(tiers))
	normalizedTiers := make([]string, 0, len(tiers))
	for _, tier := range tiers {
		if tier == "" {
			continue
		}
		if _, exists := seen[tier]; exists {
			continue
		}
		seen[tier] = struct{}{}
		normalizedTiers = append(normalizedTiers, tier)
	}

	sort.Strings(normalizedTiers)
	for _, tier := range normalizedTiers {
		keys = append(keys, "snapshot_retention_tiers."+tier)
		keys = append(keys, "snapshot_retention_tiers."+tier+".older_than")
		keys = append(keys, "snapshot_retention_tiers."+tier+".keep_min")
	}

	sort.Strings(keys)
	return keys
}
