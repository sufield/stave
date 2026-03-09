package snapshot

import (
	"time"

	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/internal/pkg/timeutil"
	"github.com/sufield/stave/internal/pruner"
)

// planBuildParams holds all inputs for buildPlan (pure, testable).
type planBuildParams struct {
	Now         time.Time
	ObsRoot     string
	ArchiveDir  string
	DefaultTier string
	TierRules   []projconfig.TierMappingRule
	Tiers       projconfig.RetentionTiersMap
	Files       []snapshotFile
	Apply       bool
	Force       bool
}

func buildPlan(params planBuildParams) planOutput {
	return pruner.BuildSnapshotPlan(toPrunerBuildParams(params))
}

func toPrunerBuildParams(params planBuildParams) pruner.BuildSnapshotPlanParams {
	cmdRules := params.TierRules
	return pruner.BuildSnapshotPlanParams{
		Now:                params.Now,
		ObsRoot:            params.ObsRoot,
		ArchiveDir:         params.ArchiveDir,
		DefaultTier:        params.DefaultTier,
		TierRules:          toPrunerTierRules(params.TierRules),
		Tiers:              toPrunerRetentionTiers(params.Tiers),
		Files:              params.Files,
		Apply:              params.Apply,
		Force:              params.Force,
		DefaultOlderThan:   projconfig.DefaultSnapshotRetention,
		DefaultKeepMin:     projconfig.DefaultTierKeepMin,
		ParseDuration:      timeutil.ParseDuration,
		ResolveTierForPath: newPrunerTierResolver(cmdRules),
	}
}

func newPrunerTierResolver(rules []projconfig.TierMappingRule) func(string, []pruner.TierMappingRule, string) string {
	return func(relPath string, _ []pruner.TierMappingRule, defaultTier string) string {
		return projconfig.ResolveTierForPath(relPath, rules, defaultTier)
	}
}

func toPrunerTierRules(in []projconfig.TierMappingRule) []pruner.TierMappingRule {
	out := make([]pruner.TierMappingRule, 0, len(in))
	for _, rule := range in {
		out = append(out, pruner.TierMappingRule{
			Pattern: rule.Pattern,
			Tier:    rule.Tier,
		})
	}
	return out
}

func toPrunerRetentionTiers(in projconfig.RetentionTiersMap) map[string]pruner.RetentionTier {
	out := make(map[string]pruner.RetentionTier, len(in))
	for name, tier := range in {
		out[name] = pruner.RetentionTier{
			OlderThan: tier.OlderThan,
			KeepMin:   tier.EffectiveKeepMin(),
		}
	}
	return out
}

func applyPlan(plan planOutput, obsRoot, archiveDir string, allowSymlink bool) error {
	_, err := pruner.ApplySnapshotPlan(pruner.SnapshotPlanApplyInput{
		Entries:          toPrunerPlanEntries(plan.Files),
		ObservationsRoot: obsRoot,
		ArchiveDir:       archiveDir,
		AllowSymlink:     allowSymlink,
	})
	return err
}

func toPrunerPlanEntries(entries []planFileEntry) []pruner.PlanEntry {
	out := make([]pruner.PlanEntry, 0, len(entries))
	for _, entry := range entries {
		out = append(out, pruner.PlanEntry{
			RelPath: entry.RelPath,
			Action:  entry.Action,
		})
	}
	return out
}
