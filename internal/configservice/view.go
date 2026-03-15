package configservice

import (
	"slices"
	"strings"

	"github.com/sufield/stave/internal/domain/retention"
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
	ConfigFile               string                          `json:"config_file,omitempty"`
	UserConfigFile           string                          `json:"user_config_file,omitempty"`
	ProjectRoot              string                          `json:"project_root,omitempty"`
	MaxUnsafe                ResolvedField                   `json:"max_unsafe"`
	SnapshotRetention        ResolvedField                   `json:"snapshot_retention"`
	DefaultRetentionTier     ResolvedField                   `json:"default_retention_tier"`
	CIFailurePolicy          ResolvedField                   `json:"ci_failure_policy"`
	CLIOutput                ResolvedField                   `json:"cli_output"`
	CLIQuiet                 ResolvedField                   `json:"cli_quiet"`
	CLISanitize              ResolvedField                   `json:"cli_sanitize"`
	CLIPathMode              ResolvedField                   `json:"cli_path_mode"`
	CLIAllowUnknownInput     ResolvedField                   `json:"cli_allow_unknown_input"`
	DefinedRetentionTiers    map[string]retention.TierConfig `json:"defined_retention_tiers"`
	EffectiveRetentionByTier map[string]ResolvedField        `json:"effective_retention_by_tier"`
}

// BuildKeyCompletions generates a deterministic list of valid configuration keys
// for shell completion or validation, including hierarchical retention tier paths.
func BuildKeyCompletions(baseKeys []string, tiers []string) []string {
	keys := make([]string, 0, len(baseKeys)+(len(tiers)*3))
	keys = append(keys, baseKeys...)

	t := slices.Clone(tiers)
	t = slices.DeleteFunc(t, func(s string) bool {
		return strings.TrimSpace(s) == ""
	})
	slices.Sort(t)
	t = slices.Compact(t)

	for _, tier := range t {
		prefix := "snapshot_retention_tiers." + tier
		keys = append(keys, prefix)
		keys = append(keys, prefix+".older_than")
		keys = append(keys, prefix+".keep_min")
	}

	slices.Sort(keys)
	return keys
}
