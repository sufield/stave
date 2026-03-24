package config

import (
	"os"
	"strings"

	"github.com/sufield/stave/internal/env"
)

// Evaluator handles the logic of merging configuration from multiple layers.
// All configuration state is loaded upfront, making resolution deterministic
// and free of hidden side effects (no filesystem reads during resolution).
type Evaluator struct {
	Project     *ProjectConfig
	ProjectPath string
	User        *UserConfig
	UserPath    string
}

// NewEvaluator creates a pre-populated evaluator.
func NewEvaluator(proj *ProjectConfig, projPath string, user *UserConfig, userPath string) *Evaluator {
	return &Evaluator{
		Project:     proj,
		ProjectPath: projPath,
		User:        user,
		UserPath:    userPath,
	}
}

// WithProject returns a shallow copy of the evaluator with a different project config.
// Used by the config service bridge when resolving values for a mutated config.
func (e *Evaluator) WithProject(proj *ProjectConfig, projPath string) *Evaluator {
	return &Evaluator{
		Project:     proj,
		ProjectPath: projPath,
		User:        e.User,
		UserPath:    e.UserPath,
	}
}

func (e *Evaluator) resolve(
	entry env.Entry,
	configKey string,
	projectField func(*ProjectConfig) string,
	userField func(*UserConfig) string,
	defaultValue string,
	normalize func(string) string,
) Value[string] {
	if v := strings.TrimSpace(os.Getenv(entry.Name)); v != "" {
		return Value[string]{Value: normalize(v), Source: "env:" + entry.Name, Layer: LayerEnvironment}
	}
	if e.Project != nil {
		if v := strings.TrimSpace(projectField(e.Project)); v != "" {
			return Value[string]{Value: normalize(v), Source: e.ProjectPath + ":" + configKey, Layer: LayerProjectConfig}
		}
	}
	if e.User != nil {
		if v := strings.TrimSpace(userField(e.User)); v != "" {
			return Value[string]{Value: normalize(v), Source: e.UserPath + ":" + configKey, Layer: LayerUserConfig}
		}
	}
	return Value[string]{Value: defaultValue, Source: "default", Layer: LayerDefault}
}

func passthrough(v string) string { return v }

// ResolveMaxUnsafe is the reflection target for config key "max_unsafe".
// Called by ResolveKey via reflect.MethodByName("ResolveMaxUnsafe").
func (e *Evaluator) ResolveMaxUnsafe() Value[string] { return e.ResolveMaxUnsafeDuration() }

// ResolveMaxUnsafeDuration returns the max-unsafe value with provenance.
func (e *Evaluator) ResolveMaxUnsafeDuration() Value[string] {
	return e.resolve(env.MaxUnsafe, "max_unsafe",
		func(c *ProjectConfig) string { return c.MaxUnsafe },
		func(c *UserConfig) string { return c.MaxUnsafe },
		DefaultMaxUnsafeDuration, passthrough,
	)
}

// ResolveRetentionTier returns the retention tier value with provenance.
func (e *Evaluator) ResolveRetentionTier() Value[string] {
	return e.resolve(env.RetentionTier, "default_retention_tier",
		func(c *ProjectConfig) string { return c.RetentionTier },
		func(c *UserConfig) string { return c.RetentionTier },
		DefaultRetentionTier, NormalizeTier,
	)
}

// ResolveSnapshotRetention returns the snapshot retention value with provenance for a specific tier.
func (e *Evaluator) ResolveSnapshotRetention(tier string) Value[string] {
	if v := strings.TrimSpace(os.Getenv(env.SnapshotRetention.Name)); v != "" {
		return Value[string]{Value: v, Source: "env:" + env.SnapshotRetention.Name, Layer: LayerEnvironment}
	}
	if v, ok := e.retentionFromProject(tier); ok {
		return v
	}
	if e.User != nil {
		if v := strings.TrimSpace(e.User.SnapshotRetention); v != "" {
			return Value[string]{Value: v, Source: e.UserPath + ":snapshot_retention", Layer: LayerUserConfig}
		}
	}
	return Value[string]{Value: DefaultSnapshotRetention, Source: "default", Layer: LayerDefault}
}

func (e *Evaluator) retentionFromProject(tier string) (Value[string], bool) {
	if e.Project == nil {
		return Value[string]{}, false
	}
	normalizedTier := NormalizeTier(tier)
	if tc, exists := e.Project.RetentionTiers[normalizedTier]; exists {
		if v := strings.TrimSpace(tc.OlderThan); v != "" {
			return Value[string]{
				Value:  v,
				Source: e.ProjectPath + ":snapshot_retention_tiers." + normalizedTier,
				Layer:  LayerProjectConfig,
			}, true
		}
	}
	if v := strings.TrimSpace(e.Project.SnapshotRetention); v != "" {
		return Value[string]{Value: v, Source: e.ProjectPath + ":snapshot_retention", Layer: LayerProjectConfig}, true
	}
	return Value[string]{}, false
}

// ResolveCIFailurePolicy returns the CI failure policy value with provenance.
func (e *Evaluator) ResolveCIFailurePolicy() Value[string] {
	return e.resolve(env.CIFailurePolicy, "ci_failure_policy",
		func(c *ProjectConfig) string { return c.CIFailurePolicy },
		func(c *UserConfig) string { return c.CIFailurePolicy },
		string(GatePolicyAny), passthrough,
	)
}

// ResolveCLIOutput returns the CLI output format value with provenance.
func (e *Evaluator) ResolveCLIOutput() Value[string] {
	if e.User != nil {
		v := strings.ToLower(strings.TrimSpace(e.User.CLIDefaults.Output))
		if v == "json" || v == "text" {
			return Value[string]{Value: v, Source: e.UserPath + ":cli_defaults.output", Layer: LayerUserConfig}
		}
	}
	return Value[string]{Value: "text", Source: "default", Layer: LayerDefault}
}

// ResolveCLIQuiet returns the CLI quiet value with provenance.
func (e *Evaluator) ResolveCLIQuiet() Value[bool] {
	if e.User != nil && e.User.CLIDefaults.Quiet != nil {
		return Value[bool]{Value: *e.User.CLIDefaults.Quiet, Source: e.UserPath + ":cli_defaults.quiet", Layer: LayerUserConfig}
	}
	return Value[bool]{Value: false, Source: "default", Layer: LayerDefault}
}

// ResolveCLISanitize returns the CLI sanitize value with provenance.
func (e *Evaluator) ResolveCLISanitize() Value[bool] {
	if e.User != nil && e.User.CLIDefaults.Sanitize != nil {
		return Value[bool]{Value: *e.User.CLIDefaults.Sanitize, Source: e.UserPath + ":cli_defaults.sanitize", Layer: LayerUserConfig}
	}
	return Value[bool]{Value: false, Source: "default", Layer: LayerDefault}
}

// ResolveCLIPathMode returns the CLI path mode value with provenance.
func (e *Evaluator) ResolveCLIPathMode() Value[string] {
	if e.User != nil {
		v := strings.ToLower(strings.TrimSpace(e.User.CLIDefaults.PathMode))
		if v == "base" || v == "full" {
			return Value[string]{Value: v, Source: e.UserPath + ":cli_defaults.path_mode", Layer: LayerUserConfig}
		}
	}
	return Value[string]{Value: "base", Source: "default", Layer: LayerDefault}
}

// ResolveCLIAllowUnknownInput returns the CLI allow-unknown-input value with provenance.
func (e *Evaluator) ResolveCLIAllowUnknownInput() Value[bool] {
	if e.User != nil && e.User.CLIDefaults.AllowUnknownInput != nil {
		return Value[bool]{Value: *e.User.CLIDefaults.AllowUnknownInput, Source: e.UserPath + ":cli_defaults.allow_unknown_input", Layer: LayerUserConfig}
	}
	return Value[bool]{Value: false, Source: "default", Layer: LayerDefault}
}

// --- Value-Only Accessors ---

// MaxUnsafeDuration returns the effective max-unsafe duration string.
func (e *Evaluator) MaxUnsafeDuration() string {
	return e.ResolveMaxUnsafeDuration().Value
}

// SnapshotRetention returns the retention for the current default tier.
func (e *Evaluator) SnapshotRetention() string {
	return e.SnapshotRetentionForTier(e.RetentionTier())
}

// SnapshotRetentionForTier returns the retention duration for a specific tier.
func (e *Evaluator) SnapshotRetentionForTier(tier string) string {
	return e.ResolveSnapshotRetention(tier).Value
}

// RetentionTier returns the default retention tier name.
func (e *Evaluator) RetentionTier() string {
	return e.ResolveRetentionTier().Value
}

// HasConfiguredTier checks if a specific tier exists in the project configuration.
func (e *Evaluator) HasConfiguredTier(tier string) bool {
	if e.Project == nil || len(e.Project.RetentionTiers) == 0 {
		return false
	}
	_, exists := e.Project.RetentionTiers[NormalizeTier(tier)]
	return exists
}

// CIFailurePolicy returns the failure policy as a typed GatePolicy.
func (e *Evaluator) CIFailurePolicy() GatePolicy {
	return GatePolicy(e.ResolveCIFailurePolicy().Value)
}

// --- CLI Default Accessors ---

// Quiet returns whether quiet mode is enabled by default.
func (e *Evaluator) Quiet() bool {
	return e.ResolveCLIQuiet().Value
}

// Sanitize returns whether output sanitization is enabled by default.
func (e *Evaluator) Sanitize() bool {
	return e.ResolveCLISanitize().Value
}

// PathMode returns the preferred path display mode ("base" or "full").
func (e *Evaluator) PathMode() string {
	return e.ResolveCLIPathMode().Value
}

// AllowUnknownInput returns whether to allow unknown snapshots.
func (e *Evaluator) AllowUnknownInput() bool {
	return e.ResolveCLIAllowUnknownInput().Value
}
