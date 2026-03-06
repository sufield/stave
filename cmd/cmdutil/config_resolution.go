package cmdutil

import (
	"os"
	"strings"

	"github.com/sufield/stave/internal/configservice"
	"github.com/sufield/stave/internal/envvar"
	"github.com/sufield/stave/internal/pkg/timeutil"
)

// ResolveMaxUnsafeWithSource returns max-unsafe and its source.
func ResolveMaxUnsafeWithSource(cfg *ProjectConfig, cfgPath string) ResolvedConfigValue {
	if v := strings.TrimSpace(os.Getenv(envvar.MaxUnsafe.Name)); v != "" {
		return ResolvedConfigValue{Value: v, Source: "env:" + envvar.MaxUnsafe.Name}
	}
	if cfg != nil {
		if v := strings.TrimSpace(cfg.MaxUnsafe); v != "" {
			return ResolvedConfigValue{Value: v, Source: cfgPath + ":max_unsafe"}
		}
	}
	if userCfg, userPath, ok := FindUserConfigWithPath(); ok {
		if v := strings.TrimSpace(userCfg.MaxUnsafe); v != "" {
			return ResolvedConfigValue{Value: v, Source: userPath + ":max_unsafe"}
		}
	}
	return ResolvedConfigValue{Value: DefaultMaxUnsafeDuration, Source: "default"}
}

// ResolveRetentionTierWithSource returns the retention tier and its source.
func ResolveRetentionTierWithSource(cfg *ProjectConfig, cfgPath string) ResolvedConfigValue {
	if v := strings.TrimSpace(os.Getenv(envvar.RetentionTier.Name)); v != "" {
		return ResolvedConfigValue{Value: NormalizeRetentionTier(v), Source: "env:" + envvar.RetentionTier.Name}
	}
	if cfg != nil {
		if v := strings.TrimSpace(cfg.RetentionTier); v != "" {
			return ResolvedConfigValue{Value: NormalizeRetentionTier(v), Source: cfgPath + ":default_retention_tier"}
		}
	}
	if userCfg, userPath, ok := FindUserConfigWithPath(); ok {
		if v := strings.TrimSpace(userCfg.RetentionTier); v != "" {
			return ResolvedConfigValue{Value: NormalizeRetentionTier(v), Source: userPath + ":default_retention_tier"}
		}
	}
	return ResolvedConfigValue{Value: DefaultRetentionTier, Source: "default"}
}

// ResolveSnapshotRetentionWithSource returns retention value and source for a tier.
func ResolveSnapshotRetentionWithSource(cfg *ProjectConfig, cfgPath, tier string) ResolvedConfigValue {
	if v := strings.TrimSpace(os.Getenv(envvar.SnapshotRetention.Name)); v != "" {
		return ResolvedConfigValue{Value: v, Source: "env:" + envvar.SnapshotRetention.Name}
	}
	if v, ok := resolveRetentionFromProject(cfg, cfgPath, tier); ok {
		return v
	}
	if v, ok := resolveRetentionFromUser(); ok {
		return v
	}
	return ResolvedConfigValue{Value: DefaultSnapshotRetention, Source: "default"}
}

func resolveRetentionFromProject(cfg *ProjectConfig, cfgPath, tier string) (ResolvedConfigValue, bool) {
	if cfg == nil {
		return ResolvedConfigValue{}, false
	}
	normalizedTier := NormalizeRetentionTier(tier)
	if tc, exists := cfg.RetentionTiers[normalizedTier]; exists {
		if v := strings.TrimSpace(tc.OlderThan); v != "" {
			return ResolvedConfigValue{
				Value:  v,
				Source: cfgPath + ":snapshot_retention_tiers." + normalizedTier,
			}, true
		}
	}
	if v := strings.TrimSpace(cfg.SnapshotRetention); v != "" {
		return ResolvedConfigValue{Value: v, Source: cfgPath + ":snapshot_retention"}, true
	}
	return ResolvedConfigValue{}, false
}

func resolveRetentionFromUser() (ResolvedConfigValue, bool) {
	if userCfg, userPath, ok := FindUserConfigWithPath(); ok {
		if v := strings.TrimSpace(userCfg.SnapshotRetention); v != "" {
			return ResolvedConfigValue{Value: v, Source: userPath + ":snapshot_retention"}, true
		}
	}
	return ResolvedConfigValue{}, false
}

// ResolveCIFailurePolicyWithSource returns CI failure policy and source.
func ResolveCIFailurePolicyWithSource(cfg *ProjectConfig, cfgPath string) ResolvedConfigValue {
	if v := strings.TrimSpace(os.Getenv(envvar.CIFailurePolicy.Name)); v != "" {
		return ResolvedConfigValue{Value: v, Source: "env:" + envvar.CIFailurePolicy.Name}
	}
	if cfg != nil {
		if v := strings.TrimSpace(cfg.CIFailurePolicy); v != "" {
			return ResolvedConfigValue{Value: v, Source: cfgPath + ":ci_failure_policy"}
		}
	}
	if userCfg, userPath, ok := FindUserConfigWithPath(); ok {
		if v := strings.TrimSpace(userCfg.CIFailurePolicy); v != "" {
			return ResolvedConfigValue{Value: v, Source: userPath + ":ci_failure_policy"}
		}
	}
	return ResolvedConfigValue{Value: DefaultCIFailurePolicy, Source: "default"}
}

// ResolveCLIOutputWithSource returns output mode and source.
func ResolveCLIOutputWithSource() ResolvedConfigValue {
	if cfg, path, ok := FindUserConfigWithPath(); ok {
		v := strings.ToLower(strings.TrimSpace(cfg.CLIDefaults.Output))
		if v == "json" || v == "text" {
			return ResolvedConfigValue{Value: v, Source: path + ":cli_defaults.output"}
		}
	}
	return ResolvedConfigValue{Value: "text", Source: "default"}
}

// ResolveCLIQuietWithSource returns quiet mode and source.
func ResolveCLIQuietWithSource() ResolvedConfigValue {
	if cfg, path, ok := FindUserConfigWithPath(); ok && cfg.CLIDefaults.Quiet != nil {
		if *cfg.CLIDefaults.Quiet {
			return ResolvedConfigValue{Value: "true", Source: path + ":cli_defaults.quiet"}
		}
		return ResolvedConfigValue{Value: "false", Source: path + ":cli_defaults.quiet"}
	}
	return ResolvedConfigValue{Value: "false", Source: "default"}
}

// ResolveCLISanitizeWithSource returns sanitize mode and source.
func ResolveCLISanitizeWithSource() ResolvedConfigValue {
	if cfg, path, ok := FindUserConfigWithPath(); ok && cfg.CLIDefaults.Sanitize != nil {
		if *cfg.CLIDefaults.Sanitize {
			return ResolvedConfigValue{Value: "true", Source: path + ":cli_defaults.sanitize"}
		}
		return ResolvedConfigValue{Value: "false", Source: path + ":cli_defaults.sanitize"}
	}
	return ResolvedConfigValue{Value: "false", Source: "default"}
}

// ResolveCLIPathModeWithSource returns path mode and source.
func ResolveCLIPathModeWithSource() ResolvedConfigValue {
	if cfg, path, ok := FindUserConfigWithPath(); ok {
		v := strings.ToLower(strings.TrimSpace(cfg.CLIDefaults.PathMode))
		if v == "base" || v == "full" {
			return ResolvedConfigValue{Value: v, Source: path + ":cli_defaults.path_mode"}
		}
	}
	return ResolvedConfigValue{Value: "base", Source: "default"}
}

// ResolveCLIAllowUnknownInputWithSource returns allow-unknown-input and source.
func ResolveCLIAllowUnknownInputWithSource() ResolvedConfigValue {
	if cfg, path, ok := FindUserConfigWithPath(); ok && cfg.CLIDefaults.AllowUnknownInput != nil {
		if *cfg.CLIDefaults.AllowUnknownInput {
			return ResolvedConfigValue{Value: "true", Source: path + ":cli_defaults.allow_unknown_input"}
		}
		return ResolvedConfigValue{Value: "false", Source: path + ":cli_defaults.allow_unknown_input"}
	}
	return ResolvedConfigValue{Value: "false", Source: "default"}
}

// ResolveDefinedRetentionTiers returns the defined retention tiers from project config.
func ResolveDefinedRetentionTiers(cfg *ProjectConfig) map[string]RetentionTierConfig {
	if cfg == nil || len(cfg.RetentionTiers) == 0 {
		return nil
	}
	out := make(map[string]RetentionTierConfig, len(cfg.RetentionTiers))
	for name, tc := range cfg.RetentionTiers {
		out[NormalizeRetentionTier(name)] = tc
	}
	return out
}

// Config service conversion helpers.

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
		out.RetentionTiers = make(RetentionTiersMap, len(cfg.RetentionTiers))
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
	dst.RetentionTiers = make(RetentionTiersMap, len(src.RetentionTiers))
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
	return NormalizeRetentionTier(value)
}

func (staveConfigValidator) NormalizePolicy(value string) (configservice.CIFailurePolicy, error) {
	policy, err := NormalizeGatePolicy(value)
	if err != nil {
		return "", err
	}
	return configservice.CIFailurePolicy(policy), nil
}

type staveKeepMinResolver struct{}

func (staveKeepMinResolver) EffectiveKeepMin(keepMin int) int {
	return RetentionTierConfig{KeepMin: keepMin}.EffectiveKeepMin()
}

type staveConfigResolver struct{}

func (staveConfigResolver) MaxUnsafe(cfg *configservice.Config, cfgPath string) configservice.ValueSource {
	v := ResolveMaxUnsafeWithSource(ToProjectConfig(cfg), cfgPath)
	return configservice.ValueSource{Value: v.Value, Source: v.Source}
}

func (staveConfigResolver) SnapshotRetention(cfg *configservice.Config, cfgPath, fallbackTier string) configservice.ValueSource {
	v := ResolveSnapshotRetentionWithSource(ToProjectConfig(cfg), cfgPath, fallbackTier)
	return configservice.ValueSource{Value: v.Value, Source: v.Source}
}

func (staveConfigResolver) RetentionTier(cfg *configservice.Config, cfgPath string) configservice.ValueSource {
	v := ResolveRetentionTierWithSource(ToProjectConfig(cfg), cfgPath)
	return configservice.ValueSource{Value: v.Value, Source: v.Source}
}

func (staveConfigResolver) CIFailurePolicy(cfg *configservice.Config, cfgPath string) configservice.ValueSource {
	v := ResolveCIFailurePolicyWithSource(ToProjectConfig(cfg), cfgPath)
	return configservice.ValueSource{Value: v.Value, Source: v.Source}
}

// ConfigKeyService is the shared config service instance.
var ConfigKeyService = configservice.New(ProjectConfigFile, staveConfigValidator{}, staveConfigResolver{}, staveKeepMinResolver{})
