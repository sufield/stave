// Package config provides layered configuration resolution for Stave.
//
// Configuration values are resolved in priority order:
// environment variable > workspace policy > operator settings > built-in default.
// Each resolved value carries provenance metadata (source and layer).
package config

import (
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// Constants for config files and built-in defaults.
const (
	AuditPolicyFile          = "stave.yaml"
	DefaultMaxUnsafeDuration = "168h"
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

// IsSLAPolicy reports whether this gate is the SLA-fast-fail policy
// (fail_on_overdue_upcoming). Replaces the (policy == GateSLA) probe
// in cmd/enforce/gate so the literal stays on the type.
func (g EnforcementGate) IsSLAPolicy() bool {
	return g == GateSLA
}

// SkipsMaxUnsafe reports whether this gate policy bypasses the
// max-unsafe-duration check. The SLA gate evaluates SLA-overdue and
// upcoming-breach signals only, so it ignores max-unsafe; the other
// gates apply it.
func (g EnforcementGate) SkipsMaxUnsafe() bool {
	return g == GateSLA
}

// RequiresTeamScope reports whether this gate policy is compatible
// with a --team filter. The SLA gate scopes globally and ignores
// team scoping; the strict and regression gates can be team-scoped.
// Replaces the (Policy != GateSLA) part of the team-gating compound
// condition.
func (g EnforcementGate) RequiresTeamScope() bool {
	return g != GateSLA
}

// ParseEnforcementGate validates and normalizes a string into an EnforcementGate.
func ParseEnforcementGate(raw string) (EnforcementGate, error) {
	trimmed := strings.TrimSpace(raw)
	if strings.EqualFold(trimmed, string(GateStrict)) {
		return GateStrict, nil
	}
	if strings.EqualFold(trimmed, string(GateRegression)) {
		return GateRegression, nil
	}
	if strings.EqualFold(trimmed, string(GateSLA)) {
		return GateSLA, nil
	}
	return "", fmt.Errorf("unsupported enforcement gate %q (supported: %s, %s, %s)",
		raw, GateStrict, GateRegression, GateSLA)
}

// --- Governance Models ---

// WorkspacePolicy represents the security requirements for a repository (stave.yaml).
//
// Fields tagged `governance:"include"` are exposed as settable /
// inspectable governance settings via GovernanceSettings. The
// opt-in tag replaces the previous reflect-on-Kind heuristic — that
// shape silently inflated the settings surface every time a new
// scalar field landed, and silently dropped fields that switched
// from string to a typed wrapper. The tag makes governance
// membership explicit at the field site.
type WorkspacePolicy struct {
	MaxUnsafe                string             `yaml:"max_unsafe"                   governance:"include"`
	CIFailurePolicy          string             `yaml:"ci_failure_policy"            governance:"include"`
	CaptureCadence           string             `yaml:"capture_cadence"              governance:"include"`
	SnapshotFilenameTemplate string             `yaml:"snapshot_filename_template"   governance:"include"`
	Exceptions               []PolicyException  `yaml:"exceptions"`
	EnabledControlPacks      []string           `yaml:"enabled_control_packs"`
	ExcludeControls          []kernel.ControlID `yaml:"exclude_controls"`
	MaxInputFileSize         string             `yaml:"max_input_file_size"          governance:"include"`
	MaxGapThreshold          string             `yaml:"max_gap_threshold"            governance:"include"`
	ConfidenceHighMultiplier int                `yaml:"confidence_high_multiplier"   governance:"include"`
	ConfidenceMedMultiplier  int                `yaml:"confidence_medium_multiplier" governance:"include"`
	BlockedCommands          []string           `yaml:"blocked_commands"`
	MaxValidationErrors      int                `yaml:"max_validation_errors"        governance:"include"`
	TeamManifest             string             `yaml:"team_manifest"                governance:"include"`
	OwnerTagKey              string             `yaml:"owner_tag_key"                governance:"include"`
	BudgetPeriod             string             `yaml:"budget_period"                governance:"include"`
	BudgetFailBurnRate       float64            `yaml:"budget_fail_on_burn_rate"     governance:"include"`
	BudgetFailSeverity       []string           `yaml:"budget_fail_severity"`
}

// Validate runs the same field-level validators that
// SetAuditValue applies on programmatic mutations, but in one
// pass after a YAML decode. Catches invalid duration formats,
// unknown enforcement-gate values, and bad capture cadences at
// load time instead of letting them propagate to evaluation
// where the failure mode is opaque (silent default fallback).
//
// Returns the FIRST validation error encountered; callers can
// re-run after fixing one field to surface subsequent issues.
// Used by callers that want the validation step explicit; the
// existing SetAuditValue code path also reuses validateAuditSetting
// per-field on programmatic mutations.
func (p *WorkspacePolicy) Validate() error {
	if p == nil {
		return nil
	}
	for _, field := range []string{
		"MaxUnsafe",
		"CIFailurePolicy",
		"CaptureCadence",
		"SnapshotFilenameTemplate",
	} {
		if err := validateAuditSetting(p, field); err != nil {
			return err
		}
	}
	return nil
}

// PolicyException allows a specific resource to bypass a security control.
// ControlID is validated at YAML load time via kernel.ControlID.UnmarshalYAML.
// Expires uses policy.ExpiryDate so YAML loaders parse the date once at the
// boundary; downstream callers get an IsExpired predicate without
// re-parsing strings or carrying time-zone ambiguity from a raw
// string field.
type PolicyException struct {
	ControlID kernel.ControlID  `yaml:"control_id"`
	AssetID   asset.ID          `yaml:"asset_id"`
	Reason    string            `yaml:"reason"`
	Expires   policy.ExpiryDate `yaml:"expires"`
}

// OperatorSettings represents the local preferences of the security operator.
type OperatorSettings struct {
	MaxUnsafe       string            `yaml:"max_unsafe"`
	CIFailurePolicy string            `yaml:"ci_failure_policy"`
	CLIDefaults     OperatorCLIConfig `yaml:"cli_defaults"`
	Aliases         map[string]string `yaml:"aliases,omitempty"`
}

// OperatorCLIConfig holds CLI-specific operator defaults.
type OperatorCLIConfig struct {
	Output   string `yaml:"output"`
	Quiet    *bool  `yaml:"quiet"`
	Sanitize *bool  `yaml:"sanitize"`
	PathMode string `yaml:"path_mode"`
}
