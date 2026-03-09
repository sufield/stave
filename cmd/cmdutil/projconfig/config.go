// Package cmdutil provides shared helpers for cmd sub-packages, preventing
// circular imports between cmd and its sub-packages.
package projconfig

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sufield/stave/internal/pkg/timeutil"
)

// Constants for config files and built-in defaults.
const (
	DefaultMaxUnsafeDuration            = "168h"
	DefaultSnapshotRetention            = "30d"
	DefaultRetentionTier                = "critical"
	DefaultTierKeepMin                  = 2
	DefaultCIFailurePolicy   GatePolicy = "fail_on_any_violation"
	ProjectConfigFile                   = "stave.yaml"
)

// GatePolicy represents a CI failure policy mode.
type GatePolicy string

// Gate policy constants shared by enforce and config service.
const (
	GatePolicyAny     GatePolicy = "fail_on_any_violation"
	GatePolicyNew     GatePolicy = "fail_on_new_violation"
	GatePolicyOverdue GatePolicy = "fail_on_overdue_upcoming"
)

// NormalizeGatePolicy validates and normalizes a gate policy string.
func NormalizeGatePolicy(raw string) (GatePolicy, error) {
	policy := GatePolicy(strings.ToLower(strings.TrimSpace(raw)))
	switch policy {
	case GatePolicyAny, GatePolicyNew, GatePolicyOverdue:
		return policy, nil
	default:
		return "", fmt.Errorf(
			"unsupported --policy %q (supported: %s, %s, %s)",
			raw, GatePolicyAny, GatePolicyNew, GatePolicyOverdue,
		)
	}
}

// RetentionTierConfig holds a tier's retention settings.
type RetentionTierConfig struct {
	OlderThan string `yaml:"older_than" json:"older_than"`
	KeepMin   int    `yaml:"keep_min,omitempty"   json:"keep_min"`
}

// RetentionTiersMap is a map of tier name to RetentionTierConfig.
type RetentionTiersMap map[string]RetentionTierConfig

// OlderThanDuration parses the OlderThan string as an extended duration.
func (c RetentionTierConfig) OlderThanDuration() (time.Duration, error) {
	if c.OlderThan == "" {
		return 0, fmt.Errorf("older_than is empty")
	}
	return timeutil.ParseDuration(c.OlderThan)
}

// EffectiveKeepMin returns the keep_min value, defaulting to DefaultTierKeepMin.
func (c RetentionTierConfig) EffectiveKeepMin() int {
	if c.KeepMin <= 0 {
		return DefaultTierKeepMin
	}
	return c.KeepMin
}

// TierMappingRule maps a glob pattern to a retention tier.
type TierMappingRule struct {
	Pattern string `yaml:"pattern" json:"pattern"`
	Tier    string `yaml:"tier"    json:"tier"`
}

// ResolveTierForPath returns the tier for a relative file path.
func ResolveTierForPath(relPath string, rules []TierMappingRule, defaultTier string) string {
	for _, rule := range rules {
		matched, err := MatchGlobPattern(rule.Pattern, relPath)
		if err != nil {
			continue
		}
		if matched {
			return rule.Tier
		}
	}
	return defaultTier
}

// MatchGlobPattern handles "prefix/**" (recursive) and plain filepath.Match globs.
func MatchGlobPattern(pattern, relPath string) (bool, error) {
	if after, ok := strings.CutSuffix(pattern, "/**"); ok {
		prefix := after + "/"
		return strings.HasPrefix(relPath, prefix), nil
	}
	return filepath.Match(pattern, relPath)
}

// ProjectConfig holds stave.yaml project configuration.
type ProjectConfig struct {
	MaxUnsafe                string                   `yaml:"max_unsafe"`
	SnapshotRetention        string                   `yaml:"snapshot_retention"`
	RetentionTier            string                   `yaml:"default_retention_tier"`
	RetentionTiers           RetentionTiersMap        `yaml:"snapshot_retention_tiers"`
	ObservationTierMapping   []TierMappingRule        `yaml:"observation_tier_mapping"`
	CIFailurePolicy          string                   `yaml:"ci_failure_policy"`
	CaptureCadence           string                   `yaml:"capture_cadence"`
	SnapshotFilenameTemplate string                   `yaml:"snapshot_filename_template"`
	Suppressions             []ProjectSuppressionRule `yaml:"suppressions"`
	EnabledControlPacks      []string                 `yaml:"enabled_control_packs"`
	ExcludeControls          []string                 `yaml:"exclude_controls"`
}

// ProjectSuppressionRule defines a control suppression.
type ProjectSuppressionRule struct {
	ControlID string `yaml:"control_id"`
	AssetID   string `yaml:"asset_id"`
	Reason    string `yaml:"reason"`
	Expires   string `yaml:"expires"`
}

// UserCLIConfig holds CLI-specific user defaults.
type UserCLIConfig struct {
	Output            string `yaml:"output"`
	Quiet             *bool  `yaml:"quiet"`
	Sanitize          *bool  `yaml:"sanitize"`
	PathMode          string `yaml:"path_mode"`
	AllowUnknownInput *bool  `yaml:"allow_unknown_input"`
}

// UserConfig holds user-level configuration.
type UserConfig struct {
	MaxUnsafe         string            `yaml:"max_unsafe"`
	SnapshotRetention string            `yaml:"snapshot_retention"`
	RetentionTier     string            `yaml:"default_retention_tier"`
	CIFailurePolicy   string            `yaml:"ci_failure_policy"`
	CLIDefaults       UserCLIConfig     `yaml:"cli_defaults"`
	Aliases           map[string]string `yaml:"aliases,omitempty"`
}

// ResolvedConfigValue holds a resolved value and its source.
type ResolvedConfigValue struct {
	Value  string
	Source string
}

// ResolvedBoolValue holds a resolved boolean and its source.
type ResolvedBoolValue struct {
	Bool   bool
	Source string
}

// ToConfigValue converts to ResolvedConfigValue for display.
func (v ResolvedBoolValue) ToConfigValue() ResolvedConfigValue {
	s := "false"
	if v.Bool {
		s = "true"
	}
	return ResolvedConfigValue{Value: s, Source: v.Source}
}

// NormalizeRetentionTier normalizes a tier name.
func NormalizeRetentionTier(tier string) string {
	return strings.ToLower(strings.TrimSpace(tier))
}

// SortedRetentionTierNames returns sorted tier names from a map.
func SortedRetentionTierNames(tiers RetentionTiersMap) []string {
	out := make([]string, 0, len(tiers))
	for name := range tiers {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
