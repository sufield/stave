package config

import (
	"os"
	"strings"

	"github.com/sufield/stave/internal/env"
)

// GovernanceResolver orchestrates the merging of security settings from multiple layers.
type GovernanceResolver struct {
	Policy       *ProjectConfig
	PolicyPath   string
	Settings     *UserConfig
	SettingsPath string
	Getenv       func(string) string
}

// NewResolver constructs a pre-populated governance resolver.
func NewResolver(p *ProjectConfig, pPath string, s *UserConfig, sPath string) *GovernanceResolver {
	return &GovernanceResolver{
		Policy:       p,
		PolicyPath:   pPath,
		Settings:     s,
		SettingsPath: sPath,
		Getenv:       os.Getenv,
	}
}

// WithPolicy returns a resolver with an updated security policy.
func (r *GovernanceResolver) WithPolicy(p *ProjectConfig, pPath string) *GovernanceResolver {
	return &GovernanceResolver{
		Policy:       p,
		PolicyPath:   pPath,
		Settings:     r.Settings,
		SettingsPath: r.SettingsPath,
		Getenv:       r.Getenv,
	}
}

func (r *GovernanceResolver) mergeLayers(
	entry env.Entry,
	configKey string,
	policyField func(*ProjectConfig) string,
	userField func(*UserConfig) string,
	defaultValue string,
	normalize func(string) string,
) Value[string] {
	if v := strings.TrimSpace(r.Getenv(entry.Name)); v != "" {
		return Value[string]{Value: normalize(v), Source: "env:" + entry.Name, Layer: LayerEnvironment}
	}
	if r.Policy != nil {
		if v := strings.TrimSpace(policyField(r.Policy)); v != "" {
			return Value[string]{Value: normalize(v), Source: r.PolicyPath + ":" + configKey, Layer: LayerProjectConfig}
		}
	}
	if r.Settings != nil {
		if v := strings.TrimSpace(userField(r.Settings)); v != "" {
			return Value[string]{Value: normalize(v), Source: r.SettingsPath + ":" + configKey, Layer: LayerUserConfig}
		}
	}
	return Value[string]{Value: defaultValue, Source: "default", Layer: LayerDefault}
}

func passthrough(v string) string { return v }

// ResolveMaxUnsafeDuration returns the SLA threshold with provenance.
func (r *GovernanceResolver) ResolveMaxUnsafeDuration() Value[string] {
	return r.mergeLayers(env.MaxUnsafe, "max_unsafe",
		func(c *ProjectConfig) string { return c.MaxUnsafe },
		func(c *UserConfig) string { return c.MaxUnsafe },
		DefaultMaxUnsafeDuration, passthrough,
	)
}

// ResolveRetentionTier returns the default retention tier with provenance.
func (r *GovernanceResolver) ResolveRetentionTier() Value[string] {
	return r.mergeLayers(env.RetentionTier, "default_retention_tier",
		func(c *ProjectConfig) string { return c.RetentionTier },
		func(c *UserConfig) string { return c.RetentionTier },
		DefaultRetentionTier, NormalizeTier,
	)
}

// ResolveSnapshotRetention returns the retention duration for a specific tier.
func (r *GovernanceResolver) ResolveSnapshotRetention(tier string) Value[string] {
	if v := strings.TrimSpace(r.Getenv(env.SnapshotRetention.Name)); v != "" {
		return Value[string]{Value: v, Source: "env:" + env.SnapshotRetention.Name, Layer: LayerEnvironment}
	}
	if v, ok := r.retentionFromPolicy(tier); ok {
		return v
	}
	if r.Settings != nil {
		if v := strings.TrimSpace(r.Settings.SnapshotRetention); v != "" {
			return Value[string]{Value: v, Source: r.SettingsPath + ":snapshot_retention", Layer: LayerUserConfig}
		}
	}
	return Value[string]{Value: DefaultSnapshotRetention, Source: "default", Layer: LayerDefault}
}

func (r *GovernanceResolver) retentionFromPolicy(tier string) (Value[string], bool) {
	if r.Policy == nil {
		return Value[string]{}, false
	}
	normalizedTier := NormalizeTier(tier)
	if tc, exists := r.Policy.RetentionTiers[normalizedTier]; exists {
		if v := strings.TrimSpace(tc.OlderThan); v != "" {
			return Value[string]{
				Value:  v,
				Source: r.PolicyPath + ":snapshot_retention_tiers." + normalizedTier,
				Layer:  LayerProjectConfig,
			}, true
		}
	}
	if v := strings.TrimSpace(r.Policy.SnapshotRetention); v != "" {
		return Value[string]{Value: v, Source: r.PolicyPath + ":snapshot_retention", Layer: LayerProjectConfig}, true
	}
	return Value[string]{}, false
}

// ResolveCIFailurePolicy returns the enforcement gate policy with provenance.
func (r *GovernanceResolver) ResolveCIFailurePolicy() Value[string] {
	return r.mergeLayers(env.CIFailurePolicy, "ci_failure_policy",
		func(c *ProjectConfig) string { return c.CIFailurePolicy },
		func(c *UserConfig) string { return c.CIFailurePolicy },
		string(GatePolicyAny), passthrough,
	)
}

// ResolveCLIOutput returns the CLI output format with provenance.
func (r *GovernanceResolver) ResolveCLIOutput() Value[string] {
	if r.Settings != nil {
		v := strings.ToLower(strings.TrimSpace(r.Settings.CLIDefaults.Output))
		if v == "json" || v == "text" {
			return Value[string]{Value: v, Source: r.SettingsPath + ":cli_defaults.output", Layer: LayerUserConfig}
		}
	}
	return Value[string]{Value: "text", Source: "default", Layer: LayerDefault}
}

// ResolveCLIQuiet returns the CLI quiet value with provenance.
func (r *GovernanceResolver) ResolveCLIQuiet() Value[bool] {
	if r.Settings != nil && r.Settings.CLIDefaults.Quiet != nil {
		return Value[bool]{Value: *r.Settings.CLIDefaults.Quiet, Source: r.SettingsPath + ":cli_defaults.quiet", Layer: LayerUserConfig}
	}
	return Value[bool]{Value: false, Source: "default", Layer: LayerDefault}
}

// ResolveCLISanitize returns the CLI sanitize value with provenance.
func (r *GovernanceResolver) ResolveCLISanitize() Value[bool] {
	if r.Settings != nil && r.Settings.CLIDefaults.Sanitize != nil {
		return Value[bool]{Value: *r.Settings.CLIDefaults.Sanitize, Source: r.SettingsPath + ":cli_defaults.sanitize", Layer: LayerUserConfig}
	}
	return Value[bool]{Value: false, Source: "default", Layer: LayerDefault}
}

// ResolveCLIPathMode returns the CLI path mode with provenance.
func (r *GovernanceResolver) ResolveCLIPathMode() Value[string] {
	if r.Settings != nil {
		v := strings.ToLower(strings.TrimSpace(r.Settings.CLIDefaults.PathMode))
		if v == "base" || v == "full" {
			return Value[string]{Value: v, Source: r.SettingsPath + ":cli_defaults.path_mode", Layer: LayerUserConfig}
		}
	}
	return Value[string]{Value: "base", Source: "default", Layer: LayerDefault}
}

// ResolveCLIAllowUnknownInput returns the CLI allow-unknown-input value with provenance.
func (r *GovernanceResolver) ResolveCLIAllowUnknownInput() Value[bool] {
	if r.Settings != nil && r.Settings.CLIDefaults.AllowUnknownInput != nil {
		return Value[bool]{Value: *r.Settings.CLIDefaults.AllowUnknownInput, Source: r.SettingsPath + ":cli_defaults.allow_unknown_input", Layer: LayerUserConfig}
	}
	return Value[bool]{Value: false, Source: "default", Layer: LayerDefault}
}

// --- Value-Only Accessors ---

func (r *GovernanceResolver) MaxUnsafeDuration() string {
	return r.ResolveMaxUnsafeDuration().Value
}

func (r *GovernanceResolver) SnapshotRetention() string {
	return r.SnapshotRetentionForTier(r.RetentionTier())
}

func (r *GovernanceResolver) SnapshotRetentionForTier(tier string) string {
	return r.ResolveSnapshotRetention(tier).Value
}

func (r *GovernanceResolver) RetentionTier() string {
	return r.ResolveRetentionTier().Value
}

func (r *GovernanceResolver) HasConfiguredTier(tier string) bool {
	if r.Policy == nil || len(r.Policy.RetentionTiers) == 0 {
		return false
	}
	_, exists := r.Policy.RetentionTiers[NormalizeTier(tier)]
	return exists
}

func (r *GovernanceResolver) CIFailurePolicy() GatePolicy {
	return GatePolicy(r.ResolveCIFailurePolicy().Value)
}

// --- CLI Default Accessors ---

func (r *GovernanceResolver) Quiet() bool {
	return r.ResolveCLIQuiet().Value
}

func (r *GovernanceResolver) Sanitize() bool {
	return r.ResolveCLISanitize().Value
}

func (r *GovernanceResolver) PathMode() string {
	return r.ResolveCLIPathMode().Value
}

func (r *GovernanceResolver) MaxInputFileSize() string {
	if r == nil || r.Policy == nil {
		return ""
	}
	return r.Policy.MaxInputFileSize
}

func (r *GovernanceResolver) MaxGapThreshold() string {
	if r == nil || r.Policy == nil {
		return ""
	}
	return r.Policy.MaxGapThreshold
}

func (r *GovernanceResolver) ConfidenceHighMultiplier() int {
	if r == nil || r.Policy == nil {
		return 0
	}
	return r.Policy.ConfidenceHighMultiplier
}

func (r *GovernanceResolver) ConfidenceMedMultiplier() int {
	if r == nil || r.Policy == nil {
		return 0
	}
	return r.Policy.ConfidenceMedMultiplier
}

func (r *GovernanceResolver) MaxSnapshotFiles() int {
	if r == nil || r.Policy == nil {
		return 0
	}
	return r.Policy.MaxSnapshotFiles
}

func (r *GovernanceResolver) BlockedCommands() []string {
	if r == nil || r.Policy == nil {
		return nil
	}
	return r.Policy.BlockedCommands
}

func (r *GovernanceResolver) MaxValidationErrors() int {
	if r == nil || r.Policy == nil {
		return 0
	}
	return r.Policy.MaxValidationErrors
}

func (r *GovernanceResolver) AllowUnknownInput() bool {
	return r.ResolveCLIAllowUnknownInput().Value
}
