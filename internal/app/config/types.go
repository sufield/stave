// Package config provides layered configuration resolution for Stave.
//
// Configuration values are resolved in priority order:
// environment variable > project config > user config > built-in default.
// Each resolved value carries provenance metadata (source and layer).
package config

import (
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/core/retention"
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

// Layer identifies the source of a configuration value.
type Layer int

const (
	LayerDefault       Layer = iota // built-in default value
	LayerUserConfig                 // user config (~/.config/stave/config.yaml)
	LayerProjectConfig              // project config (stave.yaml)
	LayerEnvironment                // environment variable
)

// Value holds a resolved configuration value along with its provenance metadata.
// Using generics eliminates the need for separate String/Bool structs.
type Value[T any] struct {
	Value  T
	Source string
	Layer  Layer
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

// AllGatePolicies returns all valid GatePolicy values as strings.
func AllGatePolicies() []string {
	return []string{string(GatePolicyAny), string(GatePolicyNew), string(GatePolicyOverdue)}
}

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

// --- Configuration Structs ---

// ProjectConfig represents the schema for the stave.yaml file.
type ProjectConfig struct {
	MaxUnsafe                string                    `yaml:"max_unsafe"`
	SnapshotRetention        string                    `yaml:"snapshot_retention"`
	RetentionTier            string                    `yaml:"default_retention_tier"`
	RetentionTiers           map[string]retention.Tier `yaml:"snapshot_retention_tiers"`
	ObservationTierMapping   []retention.Rule          `yaml:"observation_tier_mapping"`
	CIFailurePolicy          string                    `yaml:"ci_failure_policy"`
	CaptureCadence           string                    `yaml:"capture_cadence"`
	SnapshotFilenameTemplate string                    `yaml:"snapshot_filename_template"`
	Exceptions               []ExceptionRule           `yaml:"exceptions"`
	EnabledControlPacks      []string                  `yaml:"enabled_control_packs"`
	ExcludeControls          []string                  `yaml:"exclude_controls"`
	MaxInputFileSize         string                    `yaml:"max_input_file_size"`
	MaxGapThreshold          string                    `yaml:"max_gap_threshold"`
	ConfidenceHighMultiplier int                       `yaml:"confidence_high_multiplier"`
	ConfidenceMedMultiplier  int                       `yaml:"confidence_medium_multiplier"`
	MaxSnapshotFiles         int                       `yaml:"max_snapshot_files"`
	BlockedCommands          []string                  `yaml:"blocked_commands"`
	MaxValidationErrors      int                       `yaml:"max_validation_errors"`
}

// ExceptionRule defines a control exception.
type ExceptionRule struct {
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
