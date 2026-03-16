package projconfig

import (
	"os"
	"strings"

	"github.com/sufield/stave/internal/domain/retention"
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

// DefaultEvaluator is the package-level evaluator set during initialization.
// Use Global() to access it safely.
var DefaultEvaluator *Evaluator

// Global returns the package-level evaluator. Use of this should be minimized
// in favor of passing a local Evaluator instance where possible.
func Global() *Evaluator {
	if DefaultEvaluator == nil {
		return defaultEvaluator()
	}
	return DefaultEvaluator
}

// defaultEvaluator creates a fresh evaluator from the filesystem.
func defaultEvaluator() *Evaluator {
	pCfg, pPath, _ := FindProjectConfigWithPath("")
	uCfg, uPath, _ := FindUserConfigWithPath()
	return NewEvaluator(pCfg, pPath, uCfg, uPath)
}

// withProject returns a shallow copy of the evaluator with a different project config.
// Used by the config service bridge when resolving values for a mutated config.
func (e *Evaluator) withProject(proj *ProjectConfig, projPath string) *Evaluator {
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

func (e *Evaluator) resolveMaxUnsafe() Value[string] {
	return e.resolve(env.MaxUnsafe, "max_unsafe",
		func(c *ProjectConfig) string { return c.MaxUnsafe },
		func(c *UserConfig) string { return c.MaxUnsafe },
		DefaultMaxUnsafeDuration, passthrough,
	)
}

func (e *Evaluator) resolveRetentionTier() Value[string] {
	return e.resolve(env.RetentionTier, "default_retention_tier",
		func(c *ProjectConfig) string { return c.RetentionTier },
		func(c *UserConfig) string { return c.RetentionTier },
		DefaultRetentionTier, NormalizeTier,
	)
}

func (e *Evaluator) resolveSnapshotRetention(tier string) Value[string] {
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

func (e *Evaluator) resolveCIFailurePolicy() Value[string] {
	return e.resolve(env.CIFailurePolicy, "ci_failure_policy",
		func(c *ProjectConfig) string { return c.CIFailurePolicy },
		func(c *UserConfig) string { return c.CIFailurePolicy },
		string(GatePolicyAny), passthrough,
	)
}

func (e *Evaluator) resolveCLIOutput() Value[string] {
	if e.User != nil {
		v := strings.ToLower(strings.TrimSpace(e.User.CLIDefaults.Output))
		if v == "json" || v == "text" {
			return Value[string]{Value: v, Source: e.UserPath + ":cli_defaults.output", Layer: LayerUserConfig}
		}
	}
	return Value[string]{Value: "text", Source: "default", Layer: LayerDefault}
}

func (e *Evaluator) resolveCLIQuiet() Value[bool] {
	if e.User != nil && e.User.CLIDefaults.Quiet != nil {
		return Value[bool]{Value: *e.User.CLIDefaults.Quiet, Source: e.UserPath + ":cli_defaults.quiet", Layer: LayerUserConfig}
	}
	return Value[bool]{Value: false, Source: "default", Layer: LayerDefault}
}

func (e *Evaluator) resolveCLISanitize() Value[bool] {
	if e.User != nil && e.User.CLIDefaults.Sanitize != nil {
		return Value[bool]{Value: *e.User.CLIDefaults.Sanitize, Source: e.UserPath + ":cli_defaults.sanitize", Layer: LayerUserConfig}
	}
	return Value[bool]{Value: false, Source: "default", Layer: LayerDefault}
}

func (e *Evaluator) resolveCLIPathMode() Value[string] {
	if e.User != nil {
		v := strings.ToLower(strings.TrimSpace(e.User.CLIDefaults.PathMode))
		if v == "base" || v == "full" {
			return Value[string]{Value: v, Source: e.UserPath + ":cli_defaults.path_mode", Layer: LayerUserConfig}
		}
	}
	return Value[string]{Value: "base", Source: "default", Layer: LayerDefault}
}

func (e *Evaluator) resolveCLIAllowUnknownInput() Value[bool] {
	if e.User != nil && e.User.CLIDefaults.AllowUnknownInput != nil {
		return Value[bool]{Value: *e.User.CLIDefaults.AllowUnknownInput, Source: e.UserPath + ":cli_defaults.allow_unknown_input", Layer: LayerUserConfig}
	}
	return Value[bool]{Value: false, Source: "default", Layer: LayerDefault}
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
