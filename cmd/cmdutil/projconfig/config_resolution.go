package projconfig

import (
	"os"
	"strings"

	"github.com/sufield/stave/internal/configservice"
	"github.com/sufield/stave/internal/env"
	"github.com/sufield/stave/internal/pkg/timeutil"
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

// defaultEvaluator returns a lazily-initialized evaluator using the default
// filesystem resolver. Used by package-level convenience functions.
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

// --- Cascading Logic ---

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

// --- High-Level Resolvers ---

// MaxUnsafe returns max-unsafe and its source.
func (e *Evaluator) MaxUnsafe() Value[string] {
	return e.resolve(env.MaxUnsafe, "max_unsafe",
		func(c *ProjectConfig) string { return c.MaxUnsafe },
		func(c *UserConfig) string { return c.MaxUnsafe },
		DefaultMaxUnsafeDuration, passthrough,
	)
}

// RetentionTier returns the retention tier and its source.
func (e *Evaluator) RetentionTier() Value[string] {
	return e.resolve(env.RetentionTier, "default_retention_tier",
		func(c *ProjectConfig) string { return c.RetentionTier },
		func(c *UserConfig) string { return c.RetentionTier },
		DefaultRetentionTier, NormalizeTier,
	)
}

// SnapshotRetention returns retention value and source for a tier.
func (e *Evaluator) SnapshotRetention(tier string) Value[string] {
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

// CIFailurePolicy returns CI failure policy and source.
func (e *Evaluator) CIFailurePolicy() Value[string] {
	return e.resolve(env.CIFailurePolicy, "ci_failure_policy",
		func(c *ProjectConfig) string { return c.CIFailurePolicy },
		func(c *UserConfig) string { return c.CIFailurePolicy },
		string(GatePolicyAny), passthrough,
	)
}

// --- CLI Default Resolvers ---

// CLIOutput returns output mode and source.
func (e *Evaluator) CLIOutput() Value[string] {
	if e.User != nil {
		v := strings.ToLower(strings.TrimSpace(e.User.CLIDefaults.Output))
		if v == "json" || v == "text" {
			return Value[string]{Value: v, Source: e.UserPath + ":cli_defaults.output", Layer: LayerUserConfig}
		}
	}
	return Value[string]{Value: "text", Source: "default", Layer: LayerDefault}
}

// CLIQuiet returns quiet mode and source.
func (e *Evaluator) CLIQuiet() Value[bool] {
	if e.User != nil && e.User.CLIDefaults.Quiet != nil {
		return Value[bool]{Value: *e.User.CLIDefaults.Quiet, Source: e.UserPath + ":cli_defaults.quiet", Layer: LayerUserConfig}
	}
	return Value[bool]{Value: false, Source: "default", Layer: LayerDefault}
}

// CLISanitize returns sanitize mode and source.
func (e *Evaluator) CLISanitize() Value[bool] {
	if e.User != nil && e.User.CLIDefaults.Sanitize != nil {
		return Value[bool]{Value: *e.User.CLIDefaults.Sanitize, Source: e.UserPath + ":cli_defaults.sanitize", Layer: LayerUserConfig}
	}
	return Value[bool]{Value: false, Source: "default", Layer: LayerDefault}
}

// CLIPathMode returns path mode and source.
func (e *Evaluator) CLIPathMode() Value[string] {
	if e.User != nil {
		v := strings.ToLower(strings.TrimSpace(e.User.CLIDefaults.PathMode))
		if v == "base" || v == "full" {
			return Value[string]{Value: v, Source: e.UserPath + ":cli_defaults.path_mode", Layer: LayerUserConfig}
		}
	}
	return Value[string]{Value: "base", Source: "default", Layer: LayerDefault}
}

// CLIAllowUnknownInput returns allow-unknown-input and source.
func (e *Evaluator) CLIAllowUnknownInput() Value[bool] {
	if e.User != nil && e.User.CLIDefaults.AllowUnknownInput != nil {
		return Value[bool]{Value: *e.User.CLIDefaults.AllowUnknownInput, Source: e.UserPath + ":cli_defaults.allow_unknown_input", Layer: LayerUserConfig}
	}
	return Value[bool]{Value: false, Source: "default", Layer: LayerDefault}
}

// --- Static Helpers ---

// ResolveDefinedRetentionTiers returns the defined retention tiers from project config.
func ResolveDefinedRetentionTiers(cfg *ProjectConfig) map[string]RetentionTierConfig {
	if cfg == nil || len(cfg.RetentionTiers) == 0 {
		return nil
	}
	out := make(map[string]RetentionTierConfig, len(cfg.RetentionTiers))
	for name, tc := range cfg.RetentionTiers {
		out[NormalizeTier(name)] = tc
	}
	return out
}

// --- Config Service Integration ---

// FromProjectConfig converts a ProjectConfig to a configservice.Config.
func FromProjectConfig(cfg *ProjectConfig) *configservice.Config {
	if cfg == nil {
		return nil
	}
	out := &configservice.Config{
		MaxUnsafe:                cfg.MaxUnsafe,
		SnapshotRetention:        cfg.SnapshotRetention,
		RetentionTier:            cfg.RetentionTier,
		CIFailurePolicy:          configservice.CIFailurePolicy(cfg.CIFailurePolicy),
		CaptureCadence:           configservice.CaptureCadence(cfg.CaptureCadence),
		SnapshotFilenameTemplate: cfg.SnapshotFilenameTemplate,
	}
	if len(cfg.RetentionTiers) > 0 {
		out.RetentionTiers = make(configservice.RetentionTiers, len(cfg.RetentionTiers))
		for tier, tc := range cfg.RetentionTiers {
			out.RetentionTiers[tier] = configservice.RetentionTierConfig{OlderThan: tc.OlderThan, KeepMin: tc.KeepMin}
		}
	}
	return out
}

// ToProjectConfig converts a configservice.Config to a ProjectConfig.
func ToProjectConfig(cfg *configservice.Config) *ProjectConfig {
	if cfg == nil {
		return nil
	}
	out := &ProjectConfig{
		MaxUnsafe:                cfg.MaxUnsafe,
		SnapshotRetention:        cfg.SnapshotRetention,
		RetentionTier:            cfg.RetentionTier,
		CIFailurePolicy:          string(cfg.CIFailurePolicy),
		CaptureCadence:           string(cfg.CaptureCadence),
		SnapshotFilenameTemplate: cfg.SnapshotFilenameTemplate,
	}
	if len(cfg.RetentionTiers) > 0 {
		out.RetentionTiers = make(map[string]RetentionTierConfig, len(cfg.RetentionTiers))
		for tier, tc := range cfg.RetentionTiers {
			out.RetentionTiers[tier] = RetentionTierConfig{OlderThan: tc.OlderThan, KeepMin: tc.KeepMin}
		}
	}
	return out
}

// CopyProjectConfig copies fields from a configservice.Config into a ProjectConfig.
func CopyProjectConfig(dst *ProjectConfig, src *configservice.Config) {
	if dst == nil || src == nil {
		return
	}
	dst.MaxUnsafe = src.MaxUnsafe
	dst.SnapshotRetention = src.SnapshotRetention
	dst.RetentionTier = src.RetentionTier
	dst.CIFailurePolicy = string(src.CIFailurePolicy)
	dst.CaptureCadence = string(src.CaptureCadence)
	dst.SnapshotFilenameTemplate = src.SnapshotFilenameTemplate

	if len(src.RetentionTiers) == 0 {
		dst.RetentionTiers = nil
		return
	}
	dst.RetentionTiers = make(map[string]RetentionTierConfig, len(src.RetentionTiers))
	for tier, tc := range src.RetentionTiers {
		dst.RetentionTiers[tier] = RetentionTierConfig{OlderThan: tc.OlderThan, KeepMin: tc.KeepMin}
	}
}

// MutateProjectConfig applies a mutation function via configservice.Config translation.
func MutateProjectConfig(cfg *ProjectConfig, mutate func(*configservice.Config) error) error {
	serviceCfg := FromProjectConfig(cfg)
	if err := mutate(serviceCfg); err != nil {
		return err
	}
	CopyProjectConfig(cfg, serviceCfg)
	return nil
}

type staveConfigValidator struct{}

func (staveConfigValidator) ParseDuration(value string) error {
	_, err := timeutil.ParseDuration(value)
	return err
}

func (staveConfigValidator) NormalizeTier(value string) string {
	return NormalizeTier(value)
}

func (staveConfigValidator) NormalizePolicy(value string) (configservice.CIFailurePolicy, error) {
	policy, err := ParseGatePolicy(value)
	if err != nil {
		return "", err
	}
	return configservice.CIFailurePolicy(policy), nil
}

type staveKeepMinResolver struct{}

func (staveKeepMinResolver) EffectiveKeepMin(keepMin int) int {
	return RetentionTierConfig{KeepMin: keepMin}.EffectiveKeepMin()
}

// staveConfigResolver bridges the Evaluator to the configservice.Resolver interface.
// It creates a temporary evaluator with the service-provided project config,
// preserving the user config from the default evaluator.
type staveConfigResolver struct{}

func (staveConfigResolver) MaxUnsafe(cfg *configservice.Config, cfgPath string) configservice.ValueSource {
	v := defaultEvaluator().withProject(ToProjectConfig(cfg), cfgPath).MaxUnsafe()
	return configservice.ValueSource{Value: v.Value, Source: v.Source}
}

func (staveConfigResolver) SnapshotRetention(cfg *configservice.Config, cfgPath, fallbackTier string) configservice.ValueSource {
	v := defaultEvaluator().withProject(ToProjectConfig(cfg), cfgPath).SnapshotRetention(fallbackTier)
	return configservice.ValueSource{Value: v.Value, Source: v.Source}
}

func (staveConfigResolver) RetentionTier(cfg *configservice.Config, cfgPath string) configservice.ValueSource {
	v := defaultEvaluator().withProject(ToProjectConfig(cfg), cfgPath).RetentionTier()
	return configservice.ValueSource{Value: v.Value, Source: v.Source}
}

func (staveConfigResolver) CIFailurePolicy(cfg *configservice.Config, cfgPath string) configservice.ValueSource {
	v := defaultEvaluator().withProject(ToProjectConfig(cfg), cfgPath).CIFailurePolicy()
	return configservice.ValueSource{Value: v.Value, Source: v.Source}
}

// ConfigKeyService is the shared config service instance.
var ConfigKeyService = configservice.New(ProjectConfigFile, staveConfigValidator{}, staveConfigResolver{}, staveKeepMinResolver{})

// ConfigKeyCompletions returns config key completions including retention tier
// variants from the project config.
func ConfigKeyCompletions() []string {
	return ConfigKeyCompletionsFrom(ConfigKeyService)
}

// ConfigKeyCompletionsFrom returns config key completions using the supplied service.
func ConfigKeyCompletionsFrom(svc *configservice.Service) []string {
	if svc == nil {
		svc = ConfigKeyService
	}
	baseKeys := svc.TopLevelKeys()
	tiers := []string{DefaultRetentionTier}

	if cfg, ok := FindProjectConfig(); ok {
		if t := NormalizeTier(cfg.RetentionTier); t != "" {
			tiers = append(tiers, t)
		}
		for tier := range cfg.RetentionTiers {
			if t := NormalizeTier(tier); t != "" {
				tiers = append(tiers, t)
			}
		}
	}

	return configservice.BuildKeyCompletions(baseKeys, tiers)
}
