package config

import (
	"path/filepath"

	"github.com/sufield/stave/internal/configservice"
	"github.com/sufield/stave/internal/domain/retention"
)

// toResolvedField converts a Value[T] to a configservice.ResolvedField.
func toResolvedField[T any](v Value[T]) configservice.ResolvedField {
	return configservice.ResolvedField{Value: v.String(), Source: v.Source}
}

// BuildEffectiveConfig assembles the fully resolved configuration with provenance,
// suitable for `stave config show` output.
func (e *Evaluator) BuildEffectiveConfig() configservice.EffectiveConfig {
	retTier := e.ResolveRetentionTier()
	out := configservice.EffectiveConfig{
		DefaultRetentionTier:     toResolvedField(retTier),
		MaxUnsafe:                toResolvedField(e.ResolveMaxUnsafe()),
		SnapshotRetention:        toResolvedField(e.ResolveSnapshotRetention(retTier.Value)),
		CIFailurePolicy:          toResolvedField(e.ResolveCIFailurePolicy()),
		CLIOutput:                toResolvedField(e.ResolveCLIOutput()),
		CLIQuiet:                 toResolvedField(e.ResolveCLIQuiet()),
		CLISanitize:              toResolvedField(e.ResolveCLISanitize()),
		CLIPathMode:              toResolvedField(e.ResolveCLIPathMode()),
		CLIAllowUnknownInput:     toResolvedField(e.ResolveCLIAllowUnknownInput()),
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
		out.EffectiveRetentionByTier[tier] = toResolvedField(e.ResolveSnapshotRetention(tier))
	}
	return out
}

func (e *Evaluator) buildDefinedRetentionTiers() map[string]retention.TierConfig {
	if e.Project != nil {
		if tiers := ResolveDefinedRetentionTiers(e.Project); len(tiers) > 0 {
			return tiers
		}
	}
	return map[string]retention.TierConfig{
		DefaultRetentionTier: {OlderThan: DefaultSnapshotRetention, KeepMin: DefaultTierKeepMin},
	}
}
