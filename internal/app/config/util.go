package config

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/sufield/stave/pkg/alpha/domain/retention"
)

// NormalizeTier standardizes a tier name string.
func NormalizeTier(tier string) string {
	return strings.ToLower(strings.TrimSpace(tier))
}

// SortedTierNames returns the keys of a tier map in alphabetical order.
func SortedTierNames(tiers map[string]retention.TierConfig) []string {
	names := make([]string, 0, len(tiers))
	for name := range tiers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ResolveTierForPath identifies the appropriate tier for a file path based on glob rules.
func ResolveTierForPath(relPath string, rules []retention.MappingRule, defaultTier string) string {
	for _, rule := range rules {
		if matched, _ := MatchGlob(rule.Pattern, relPath); matched {
			return rule.Tier
		}
	}
	return defaultTier
}

// MatchGlob handles standard filepath globs and recursive "/**" suffixes.
func MatchGlob(pattern, relPath string) (bool, error) {
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "**")
		return strings.HasPrefix(relPath, prefix), nil
	}
	return filepath.Match(pattern, relPath)
}

// ResolveDefinedRetentionTiers returns the defined retention tiers from project config.
func ResolveDefinedRetentionTiers(cfg *ProjectConfig) map[string]retention.TierConfig {
	if cfg == nil || len(cfg.RetentionTiers) == 0 {
		return nil
	}
	out := make(map[string]retention.TierConfig, len(cfg.RetentionTiers))
	for name, tc := range cfg.RetentionTiers {
		out[NormalizeTier(name)] = tc
	}
	return out
}
