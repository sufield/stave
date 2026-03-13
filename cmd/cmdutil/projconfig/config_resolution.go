package projconfig

import (
	"os"
	"path/filepath"
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

// --- Cascading Logic (private — return Value[T] with provenance) ---

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

// --- Effective Config Output ---

// toResolvedField converts a Value[T] to a configservice.ResolvedField.
func toResolvedField[T any](v Value[T]) configservice.ResolvedField {
	return configservice.ResolvedField{Value: v.String(), Source: v.Source}
}

// BuildEffectiveConfig assembles the fully resolved configuration with provenance,
// suitable for `stave config show` output.
func (e *Evaluator) BuildEffectiveConfig() configservice.EffectiveConfig {
	retTier := e.resolveRetentionTier()
	out := configservice.EffectiveConfig{
		DefaultRetentionTier:     toResolvedField(retTier),
		MaxUnsafe:                toResolvedField(e.resolveMaxUnsafe()),
		SnapshotRetention:        toResolvedField(e.resolveSnapshotRetention(retTier.Value)),
		CIFailurePolicy:          toResolvedField(e.resolveCIFailurePolicy()),
		CLIOutput:                toResolvedField(e.resolveCLIOutput()),
		CLIQuiet:                 toResolvedField(e.resolveCLIQuiet()),
		CLISanitize:              toResolvedField(e.resolveCLISanitize()),
		CLIPathMode:              toResolvedField(e.resolveCLIPathMode()),
		CLIAllowUnknownInput:     toResolvedField(e.resolveCLIAllowUnknownInput()),
		DefinedRetentionTiers:    e.buildDefinedRetentionTiers(),
		EffectiveRetentionByTier: map[string]configservice.ResolvedField{},
	}
	if e.ProjectPath != "" {
		out.ConfigFile = e.ProjectPath
		out.ProjectRoot = filepath.Dir(e.ProjectPath)
	}
	if e.UserPath != "" {
		out.UserConfigFile = e.UserPath
	}
	for tier := range out.DefinedRetentionTiers {
		out.EffectiveRetentionByTier[tier] = toResolvedField(e.resolveSnapshotRetention(tier))
	}
	return out
}

func (e *Evaluator) buildDefinedRetentionTiers() map[string]configservice.RetentionTierConfig {
	if e.Project != nil {
		if tiers := ResolveDefinedRetentionTiers(e.Project); len(tiers) > 0 {
			out := make(map[string]configservice.RetentionTierConfig, len(tiers))
			for name, tier := range tiers {
				out[name] = configservice.RetentionTierConfig{OlderThan: tier.OlderThan, KeepMin: tier.KeepMin}
			}
			return out
		}
	}
	return map[string]configservice.RetentionTierConfig{
		DefaultRetentionTier: {OlderThan: DefaultSnapshotRetention, KeepMin: DefaultTierKeepMin},
	}
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
type staveConfigResolver struct{}

func (staveConfigResolver) MaxUnsafe(cfg *configservice.Config, cfgPath string) configservice.ValueSource {
	v := defaultEvaluator().withProject(ToProjectConfig(cfg), cfgPath).resolveMaxUnsafe()
	return configservice.ValueSource{Value: v.Value, Source: v.Source}
}

func (staveConfigResolver) SnapshotRetention(cfg *configservice.Config, cfgPath, fallbackTier string) configservice.ValueSource {
	v := defaultEvaluator().withProject(ToProjectConfig(cfg), cfgPath).resolveSnapshotRetention(fallbackTier)
	return configservice.ValueSource{Value: v.Value, Source: v.Source}
}

func (staveConfigResolver) RetentionTier(cfg *configservice.Config, cfgPath string) configservice.ValueSource {
	v := defaultEvaluator().withProject(ToProjectConfig(cfg), cfgPath).resolveRetentionTier()
	return configservice.ValueSource{Value: v.Value, Source: v.Source}
}

func (staveConfigResolver) CIFailurePolicy(cfg *configservice.Config, cfgPath string) configservice.ValueSource {
	v := defaultEvaluator().withProject(ToProjectConfig(cfg), cfgPath).resolveCIFailurePolicy()
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
