package config

import (
	"log/slog"
	"os"
	"strings"

	"github.com/sufield/stave/internal/env"
)

// GovernanceResolver orchestrates the merging of security settings from multiple layers.
type GovernanceResolver struct {
	Policy       *WorkspacePolicy
	PolicyPath   string
	Settings     *OperatorSettings
	SettingsPath string
	Getenv       func(string) string
}

// NewResolver constructs a pre-populated governance resolver.
func NewResolver(p *WorkspacePolicy, pPath string, s *OperatorSettings, sPath string) *GovernanceResolver {
	return &GovernanceResolver{
		Policy:       p,
		PolicyPath:   pPath,
		Settings:     s,
		SettingsPath: sPath,
		Getenv:       os.Getenv,
	}
}

// WithPolicy returns a resolver with an updated security policy.
func (r *GovernanceResolver) WithPolicy(p *WorkspacePolicy, pPath string) *GovernanceResolver {
	return &GovernanceResolver{
		Policy:       p,
		PolicyPath:   pPath,
		Settings:     r.Settings,
		SettingsPath: r.SettingsPath,
		Getenv:       r.Getenv,
	}
}

// FlagDefaultsTarget is the contract a CLI flag struct (e.g.
// cmd.globalFlagsType) satisfies so the resolver can write
// project-config defaults onto persistent flags without importing the
// CLI-side type. Each setter is invoked only when the matching flag
// was NOT changed on the command line — see ApplyUnsetDefaultsTo for
// the full precedence rule.
type FlagDefaultsTarget interface {
	SetQuiet(bool)
	SetSanitize(bool)
	// SetPathMode validates and writes the path-mode default. Errors
	// reflect a malformed config value (typo: "bsae", "absolute") —
	// callers are expected to log them rather than fail bootstrap so
	// a typo'd default does not block command execution; the
	// previously-applied (or built-in) value stays in place.
	SetPathMode(string) error
}

// Flag-key constants. The strings match the CLI flag names defined in
// cmd/cmdutil/cliflags so the cmd-side caller can pass `p.Changed`
// (which keys by CLI flag name) directly as the changed callback.
const (
	FlagKeyQuiet    = "quiet"
	FlagKeySanitize = "sanitize"
	FlagKeyPathMode = "path-mode"
)

// ApplyUnsetDefaultsTo writes project-config / user-config defaults
// onto target for every flag the operator did NOT set on the command
// line (changed(name) == false). Centralising the
// "is-flag-changed?-then-set-default" triple-check on the resolver
// removes the open-coded `if !p.Changed(...)` walk from the CLI
// bootstrap so every new resolver-driven default is one edit:
// add the setter to FlagDefaultsTarget and the entry below.
//
// A nil resolver is a no-op (matches the optional-config path's
// existing semantics — early-return rather than panic on nil).
func (r *GovernanceResolver) ApplyUnsetDefaultsTo(target FlagDefaultsTarget, changed func(string) bool) {
	if r == nil || target == nil {
		return
	}
	if changed == nil {
		changed = func(string) bool { return false }
	}
	if !changed(FlagKeyQuiet) {
		target.SetQuiet(r.Quiet())
	}
	if !changed(FlagKeySanitize) {
		target.SetSanitize(r.Sanitize())
	}
	if !changed(FlagKeyPathMode) {
		// Best-effort default. A validation error (typo'd config
		// value) is logged at WARN; bootstrap continues with the
		// previously applied value rather than failing loud — the
		// fail-loud surface for malformed PathMode is at the parser
		// layer (cliflags), not here.
		if err := target.SetPathMode(r.PathMode()); err != nil {
			slog.Warn("config: ignoring invalid path-mode default",
				"value", r.PathMode(), "error", err)
		}
	}
}

func (r *GovernanceResolver) mergeLayers(
	entry env.Entry,
	configKey string,
	policyField func(*WorkspacePolicy) string,
	userField func(*OperatorSettings) string,
	defaultValue string,
	normalize func(string) string,
) PolicyValue[string] {
	if v := strings.TrimSpace(r.Getenv(entry.Name)); v != "" {
		return PolicyValue[string]{Value: normalize(v), Source: "env:" + entry.Name, Layer: LayerEnvironment}
	}
	if r.Policy != nil {
		if v := strings.TrimSpace(policyField(r.Policy)); v != "" {
			return PolicyValue[string]{Value: normalize(v), Source: r.PolicyPath + ":" + configKey, Layer: LayerProjectConfig}
		}
	}
	if r.Settings != nil {
		if v := strings.TrimSpace(userField(r.Settings)); v != "" {
			return PolicyValue[string]{Value: normalize(v), Source: r.SettingsPath + ":" + configKey, Layer: LayerUserConfig}
		}
	}
	return PolicyValue[string]{Value: defaultValue, Source: "default", Layer: LayerDefault}
}

func passthrough(v string) string { return v }

// ResolveMaxUnsafeDuration returns the SLA threshold with provenance.
func (r *GovernanceResolver) ResolveMaxUnsafeDuration() PolicyValue[string] {
	return r.mergeLayers(env.MaxUnsafe, "max_unsafe",
		func(c *WorkspacePolicy) string { return c.MaxUnsafe },
		func(c *OperatorSettings) string { return c.MaxUnsafe },
		DefaultMaxUnsafeDuration, passthrough,
	)
}

// ResolveRetentionTier returns the default retention tier with provenance.
func (r *GovernanceResolver) ResolveRetentionTier() PolicyValue[string] {
	return r.mergeLayers(env.RetentionTier, "default_retention_tier",
		func(c *WorkspacePolicy) string { return c.RetentionTier },
		func(c *OperatorSettings) string { return c.RetentionTier },
		DefaultRetentionTier, NormalizeTier,
	)
}

// ResolveSnapshotRetention returns the retention duration for a specific tier.
func (r *GovernanceResolver) ResolveSnapshotRetention(tier string) PolicyValue[string] {
	if v := strings.TrimSpace(r.Getenv(env.SnapshotRetention.Name)); v != "" {
		return PolicyValue[string]{Value: v, Source: "env:" + env.SnapshotRetention.Name, Layer: LayerEnvironment}
	}
	if v, ok := r.retentionFromPolicy(tier); ok {
		return v
	}
	if r.Settings != nil {
		if v := strings.TrimSpace(r.Settings.SnapshotRetention); v != "" {
			return PolicyValue[string]{Value: v, Source: r.SettingsPath + ":snapshot_retention", Layer: LayerUserConfig}
		}
	}
	return PolicyValue[string]{Value: DefaultSnapshotRetention, Source: "default", Layer: LayerDefault}
}

func (r *GovernanceResolver) retentionFromPolicy(tier string) (PolicyValue[string], bool) {
	if r.Policy == nil {
		return PolicyValue[string]{}, false
	}
	normalizedTier := NormalizeTier(tier)
	if tc, exists := r.Policy.RetentionTiers[normalizedTier]; exists {
		if v := strings.TrimSpace(tc.OlderThan); v != "" {
			return PolicyValue[string]{
				Value:  v,
				Source: r.PolicyPath + ":snapshot_retention_tiers." + normalizedTier,
				Layer:  LayerProjectConfig,
			}, true
		}
	}
	if v := strings.TrimSpace(r.Policy.SnapshotRetention); v != "" {
		return PolicyValue[string]{Value: v, Source: r.PolicyPath + ":snapshot_retention", Layer: LayerProjectConfig}, true
	}
	return PolicyValue[string]{}, false
}

// ResolveCIFailurePolicy returns the enforcement gate policy with provenance.
func (r *GovernanceResolver) ResolveCIFailurePolicy() PolicyValue[string] {
	return r.mergeLayers(env.CIFailurePolicy, "ci_failure_policy",
		func(c *WorkspacePolicy) string { return c.CIFailurePolicy },
		func(c *OperatorSettings) string { return c.CIFailurePolicy },
		string(GateStrict), passthrough,
	)
}

// ResolveCLIOutput returns the CLI output format with provenance.
func (r *GovernanceResolver) ResolveCLIOutput() PolicyValue[string] {
	if r.Settings != nil {
		raw := r.Settings.CLIDefaults.Output
		v := strings.ToLower(strings.TrimSpace(raw))
		if v == "json" || v == "text" {
			return PolicyValue[string]{Value: v, Source: r.SettingsPath + ":cli_defaults.output", Layer: LayerUserConfig}
		}
		if v != "" {
			// Non-empty but invalid: silently falling back to
			// "text" hid config-file typos (e.g. "Json", "yaml")
			// from operators. Surface the rejection so they can
			// fix the config; default still applies.
			slog.Warn("config: cli_defaults.output rejected; using default",
				slog.String("invalid", raw),
				slog.String("source", r.SettingsPath),
				slog.String("default", "text"))
		}
	}
	return PolicyValue[string]{Value: "text", Source: "default", Layer: LayerDefault}
}

// ResolveCLIQuiet returns the CLI quiet value with provenance.
func (r *GovernanceResolver) ResolveCLIQuiet() PolicyValue[bool] {
	if r.Settings != nil && r.Settings.CLIDefaults.Quiet != nil {
		return PolicyValue[bool]{Value: *r.Settings.CLIDefaults.Quiet, Source: r.SettingsPath + ":cli_defaults.quiet", Layer: LayerUserConfig}
	}
	return PolicyValue[bool]{Value: false, Source: "default", Layer: LayerDefault}
}

// ResolveCLISanitize returns the CLI sanitize value with provenance.
func (r *GovernanceResolver) ResolveCLISanitize() PolicyValue[bool] {
	if r.Settings != nil && r.Settings.CLIDefaults.Sanitize != nil {
		return PolicyValue[bool]{Value: *r.Settings.CLIDefaults.Sanitize, Source: r.SettingsPath + ":cli_defaults.sanitize", Layer: LayerUserConfig}
	}
	return PolicyValue[bool]{Value: false, Source: "default", Layer: LayerDefault}
}

// ResolveCLIPathMode returns the CLI path mode with provenance.
func (r *GovernanceResolver) ResolveCLIPathMode() PolicyValue[string] {
	if r.Settings != nil {
		raw := r.Settings.CLIDefaults.PathMode
		v := strings.ToLower(strings.TrimSpace(raw))
		if v == "base" || v == "full" {
			return PolicyValue[string]{Value: v, Source: r.SettingsPath + ":cli_defaults.path_mode", Layer: LayerUserConfig}
		}
		if v != "" {
			slog.Warn("config: cli_defaults.path_mode rejected; using default",
				slog.String("invalid", raw),
				slog.String("source", r.SettingsPath),
				slog.String("default", "base"))
		}
	}
	return PolicyValue[string]{Value: "base", Source: "default", Layer: LayerDefault}
}

// ResolveCLIAllowUnknownInput returns the CLI allow-unknown-input value with provenance.
func (r *GovernanceResolver) ResolveCLIAllowUnknownInput() PolicyValue[bool] {
	if r.Settings != nil && r.Settings.CLIDefaults.AllowUnknownInput != nil {
		return PolicyValue[bool]{Value: *r.Settings.CLIDefaults.AllowUnknownInput, Source: r.SettingsPath + ":cli_defaults.allow_unknown_input", Layer: LayerUserConfig}
	}
	return PolicyValue[bool]{Value: false, Source: "default", Layer: LayerDefault}
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

func (r *GovernanceResolver) CIFailurePolicy() EnforcementGate {
	return EnforcementGate(r.ResolveCIFailurePolicy().Value)
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
