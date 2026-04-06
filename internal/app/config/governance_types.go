// Package config provides layered configuration resolution for Stave.
//
// Configuration values are resolved in priority order:
// environment variable > workspace policy > operator settings > built-in default.
// Each resolved value carries provenance metadata (source and layer).
package config

import (
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/core/retention"
)

// Constants for config files and built-in defaults.
const (
	AuditPolicyFile          = "stave.yaml"
	DefaultMaxUnsafeDuration = "168h"
	DefaultSnapshotRetention = "30d"
	DefaultRetentionTier     = "critical"
	DefaultTierKeepMin       = 2
)

// --- Policy Provenance ---

// GovernanceLayer identifies the source of a security parameter.
type GovernanceLayer int

const (
	LayerDefault       GovernanceLayer = iota // built-in default value
	LayerUserConfig                           // operator settings (~/.config/stave/config.yaml)
	LayerProjectConfig                        // workspace policy (stave.yaml)
	LayerEnvironment                          // environment variable
)

// PolicyValue wraps a setting with its provenance.
type PolicyValue[T any] struct {
	Value  T
	Source string
	Layer  GovernanceLayer
}

func (v PolicyValue[T]) String() string {
	return fmt.Sprintf("%v", v.Value)
}

// --- Enforcement Gates ---

// EnforcementGate defines how the tool behaves in CI/CD when violations are detected.
type EnforcementGate string

const (
	GateStrict     EnforcementGate = "fail_on_any_violation"
	GateRegression EnforcementGate = "fail_on_new_violation"
	GateSLA        EnforcementGate = "fail_on_overdue_upcoming"
)

// AllEnforcementGates returns the supported gate policies.
func AllEnforcementGates() []string {
	return []string{string(GateStrict), string(GateRegression), string(GateSLA)}
}

// ParseEnforcementGate validates and normalizes a string into an EnforcementGate.
func ParseEnforcementGate(raw string) (EnforcementGate, error) {
	p := EnforcementGate(strings.ToLower(strings.TrimSpace(raw)))
	switch p {
	case GateStrict, GateRegression, GateSLA:
		return p, nil
	default:
		return "", fmt.Errorf("unsupported enforcement gate %q (supported: %s, %s, %s)",
			raw, GateStrict, GateRegression, GateSLA)
	}
}

// --- Governance Models ---

// WorkspacePolicy represents the security requirements for a repository (stave.yaml).
type WorkspacePolicy struct {
	MaxUnsafe                string                    `yaml:"max_unsafe"`
	SnapshotRetention        string                    `yaml:"snapshot_retention"`
	RetentionTier            string                    `yaml:"default_retention_tier"`
	RetentionTiers           map[string]retention.Tier `yaml:"snapshot_retention_tiers"`
	ObservationTierMapping   []retention.Rule          `yaml:"observation_tier_mapping"`
	CIFailurePolicy          string                    `yaml:"ci_failure_policy"`
	CaptureCadence           string                    `yaml:"capture_cadence"`
	SnapshotFilenameTemplate string                    `yaml:"snapshot_filename_template"`
	Exceptions               []PolicyException         `yaml:"exceptions"`
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

// PolicyException allows a specific resource to bypass a security control.
type PolicyException struct {
	ControlID string `yaml:"control_id"`
	AssetID   string `yaml:"asset_id"`
	Reason    string `yaml:"reason"`
	Expires   string `yaml:"expires"`
}

// OperatorSettings represents the local preferences of the security operator.
type OperatorSettings struct {
	MaxUnsafe         string            `yaml:"max_unsafe"`
	SnapshotRetention string            `yaml:"snapshot_retention"`
	RetentionTier     string            `yaml:"default_retention_tier"`
	CIFailurePolicy   string            `yaml:"ci_failure_policy"`
	CLIDefaults       OperatorCLIConfig `yaml:"cli_defaults"`
	Aliases           map[string]string `yaml:"aliases,omitempty"`
}

// OperatorCLIConfig holds CLI-specific operator defaults.
type OperatorCLIConfig struct {
	Output            string `yaml:"output"`
	Quiet             *bool  `yaml:"quiet"`
	Sanitize          *bool  `yaml:"sanitize"`
	PathMode          string `yaml:"path_mode"`
	AllowUnknownInput *bool  `yaml:"allow_unknown_input"`
}
