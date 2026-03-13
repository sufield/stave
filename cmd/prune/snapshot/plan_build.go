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
	Tiers       map[string]projconfig.RetentionTierConfig
	Files       []snapshotFile
	Apply       bool
	Force       bool
}

func buildPlan(params planBuildParams) planOutput {
	return pruner.BuildSnapshotPlan(toPrunerBuildParams(params))
}

func toPrunerBuildParams(params planBuildParams) pruner.BuildSnapshotPlanParams {
	return pruner.BuildSnapshotPlanParams{
		Now:                params.Now,
		ObsRoot:            params.ObsRoot,
		ArchiveDir:         params.ArchiveDir,
		DefaultTier:        params.DefaultTier,
		TierRules:          params.TierRules,
		Tiers:              params.Tiers,
		Files:              params.Files,
		Apply:              params.Apply,
		Force:              params.Force,
		DefaultOlderThan:   projconfig.DefaultSnapshotRetention,
		DefaultKeepMin:     projconfig.DefaultTierKeepMin,
		ParseDuration:      timeutil.ParseDuration,
		ResolveTierForPath: projconfig.ResolveTierForPath,
	}
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
