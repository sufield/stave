package config

import (
	"log/slog"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/core/retention"
)

// NormalizeTier standardizes a tier name string.
func NormalizeTier(tier string) string {
	return strings.ToLower(strings.TrimSpace(tier))
}

// SortedTierNames returns the keys of a tier map in alphabetical order.
func SortedTierNames(tiers map[string]retention.Tier) []string {
	names := make([]string, 0, len(tiers))
	for name := range tiers {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// ResolveTierForPath identifies the appropriate tier for a file path based on glob rules.
func ResolveTierForPath(relPath string, rules []retention.Rule, defaultTier string) string {
	for _, rule := range rules {
		matched, matchErr := MatchGlob(rule.Pattern, relPath)
		if matchErr != nil {
			slog.Warn("invalid glob pattern in retention rule", "pattern", rule.Pattern, "error", matchErr)
			continue
		}
		if matched {
			return rule.Tier
		}
	}
	return defaultTier
}

// MatchGlob handles standard filepath globs and recursive "/**" suffixes.
// A "dir/**" pattern matches every descendant of `dir/` AND the bare
// directory `dir` itself — the recursive form would otherwise miss
// retention rules targeted at "snapshots/**" when the path being
// matched is the bare "snapshots" entry (which the directory walker
// produces during pruning).
func MatchGlob(pattern, relPath string) (bool, error) {
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		// Accept both "dir" (bare directory) and any descendant
		// "dir/whatever". TrimSuffix-of-"/" before equality so a
		// pattern of "dir/**" matches "dir" without trailing slash.
		if relPath == prefix {
			return true, nil
		}
		return strings.HasPrefix(relPath, prefix+"/"), nil
	}
	return filepath.Match(pattern, relPath)
}

// ResolveDefinedRetentionTiers returns the defined retention tiers from project config.
func ResolveDefinedRetentionTiers(cfg *WorkspacePolicy) map[string]retention.Tier {
	if cfg == nil || len(cfg.RetentionTiers) == 0 {
		return nil
	}
	out := make(map[string]retention.Tier, len(cfg.RetentionTiers))
	for name, tc := range cfg.RetentionTiers {
		out[NormalizeTier(name)] = tc
	}
	return out
}
