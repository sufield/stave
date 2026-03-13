// Package projconfig provides shared helpers for cmd sub-packages, preventing
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
	ProjectConfigFile        = "stave.yaml"
	DefaultMaxUnsafeDuration = "168h"
	DefaultSnapshotRetention = "30d"
	DefaultRetentionTier     = "critical"
	DefaultTierKeepMin       = 2
)

// --- Layering Logic ---

// ConfigLayer identifies the source of a configuration value.
type ConfigLayer int

const (
	LayerDefault       ConfigLayer = iota // built-in default value
	LayerUserConfig                       // user config (~/.config/stave/config.yaml)
	LayerProjectConfig                    // project config (stave.yaml)
	LayerEnvironment                      // environment variable
)

// Value holds a resolved configuration value along with its provenance metadata.
// Using generics eliminates the need for separate String/Bool structs.
type Value[T any] struct {
	Value  T
	Source string
	Layer  ConfigLayer
}

func (v Value[T]) String() string {
	return fmt.Sprintf("%v", v.Value)
}

// --- Gate Policies ---

// GatePolicy represents a CI failure policy mode.
type GatePolicy string

// Gate policy constants shared by enforce and config service.
const (
	GatePolicyAny     GatePolicy = "fail_on_any_violation"
	GatePolicyNew     GatePolicy = "fail_on_new_violation"
	GatePolicyOverdue GatePolicy = "fail_on_overdue_upcoming"
)

// ParseGatePolicy validates and normalizes a string into a GatePolicy.
func ParseGatePolicy(raw string) (GatePolicy, error) {
	p := GatePolicy(strings.ToLower(strings.TrimSpace(raw)))
	switch p {
	case GatePolicyAny, GatePolicyNew, GatePolicyOverdue:
		return p, nil
	default:
		return "", fmt.Errorf("unsupported policy %q (supported: %s, %s, %s)",
			raw, GatePolicyAny, GatePolicyNew, GatePolicyOverdue)
	}
}

// --- Retention Configuration ---

// RetentionTierConfig holds a tier's retention settings.
type RetentionTierConfig struct {
	OlderThan string `yaml:"older_than" json:"older_than"`
	KeepMin   int    `yaml:"keep_min"   json:"keep_min"`
}

// ParseDuration returns the OlderThan string as a time.Duration.
func (c RetentionTierConfig) ParseDuration() (time.Duration, error) {
	if c.OlderThan == "" {
		return 0, fmt.Errorf("older_than is empty")
	}
	return timeutil.ParseDuration(c.OlderThan)
}

// EffectiveKeepMin returns the keep_min value, using DefaultTierKeepMin as fallback.
func (c RetentionTierConfig) EffectiveKeepMin() int {
	if c.KeepMin <= 0 {
		return DefaultTierKeepMin
	}
	return c.KeepMin
}

// --- Tier Mapping Logic ---

// TierMappingRule maps a glob pattern to a retention tier.
type TierMappingRule struct {
	Pattern string `yaml:"pattern" json:"pattern"`
	Tier    string `yaml:"tier"    json:"tier"`
}

// ResolveTierForPath identifies the appropriate tier for a file path based on glob rules.
func ResolveTierForPath(relPath string, rules []TierMappingRule, defaultTier string) string {
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

// --- Configuration Structs ---

// ProjectConfig represents the schema for the stave.yaml file.
type ProjectConfig struct {
	MaxUnsafe                string                         `yaml:"max_unsafe"`
	SnapshotRetention        string                         `yaml:"snapshot_retention"`
	RetentionTier            string                         `yaml:"default_retention_tier"`
	RetentionTiers           map[string]RetentionTierConfig `yaml:"snapshot_retention_tiers"`
	ObservationTierMapping   []TierMappingRule              `yaml:"observation_tier_mapping"`
	CIFailurePolicy          string                         `yaml:"ci_failure_policy"`
	CaptureCadence           string                         `yaml:"capture_cadence"`
	SnapshotFilenameTemplate string                         `yaml:"snapshot_filename_template"`
	Suppressions             []SuppressionRule              `yaml:"suppressions"`
	EnabledControlPacks      []string                       `yaml:"enabled_control_packs"`
	ExcludeControls          []string                       `yaml:"exclude_controls"`
}

// SuppressionRule defines a control suppression.
type SuppressionRule struct {
	ControlID string `yaml:"control_id"`
	AssetID   string `yaml:"asset_id"`
	Reason    string `yaml:"reason"`
	Expires   string `yaml:"expires"`
}

// UserConfig represents the global ~/.config/stave/config.yaml file.
type UserConfig struct {
	MaxUnsafe         string            `yaml:"max_unsafe"`
	SnapshotRetention string            `yaml:"snapshot_retention"`
	RetentionTier     string            `yaml:"default_retention_tier"`
	CIFailurePolicy   string            `yaml:"ci_failure_policy"`
	CLIDefaults       UserCLIConfig     `yaml:"cli_defaults"`
	Aliases           map[string]string `yaml:"aliases,omitempty"`
}

// UserCLIConfig holds CLI-specific user defaults.
type UserCLIConfig struct {
	Output            string `yaml:"output"`
	Quiet             *bool  `yaml:"quiet"`
	Sanitize          *bool  `yaml:"sanitize"`
	PathMode          string `yaml:"path_mode"`
	AllowUnknownInput *bool  `yaml:"allow_unknown_input"`
}

// --- Utilities ---

// NormalizeTier standardizes a tier name string.
func NormalizeTier(tier string) string {
	return strings.ToLower(strings.TrimSpace(tier))
}

// SortedTierNames returns the keys of a tier map in alphabetical order.
func SortedTierNames(tiers map[string]RetentionTierConfig) []string {
	names := make([]string, 0, len(tiers))
	for name := range tiers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
