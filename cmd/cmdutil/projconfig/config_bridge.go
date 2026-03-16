package projconfig

import (
	"maps"

	"github.com/sufield/stave/internal/configservice"
	"github.com/sufield/stave/internal/domain/retention"
	"github.com/sufield/stave/internal/pkg/timeutil"
)

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
		maps.Copy(out.RetentionTiers, cfg.RetentionTiers)
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
		out.RetentionTiers = make(map[string]retention.TierConfig, len(cfg.RetentionTiers))
		maps.Copy(out.RetentionTiers, cfg.RetentionTiers)
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
	dst.RetentionTiers = make(map[string]retention.TierConfig, len(src.RetentionTiers))
	maps.Copy(dst.RetentionTiers, src.RetentionTiers)
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
	return retention.TierConfig{KeepMin: keepMin}.EffectiveKeepMin()
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
