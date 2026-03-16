package snapshot

import (
	"fmt"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/internal/domain/retention"
	"github.com/sufield/stave/internal/pkg/timeutil"
	"github.com/sufield/stave/internal/pruner"
	"github.com/sufield/stave/internal/pruner/plan"
)

// planBuildParams holds all inputs for buildPlan (pure, testable).
type planBuildParams struct {
	Now         time.Time
	ObsRoot     string
	ArchiveDir  string
	DefaultTier string
	TierRules   []retention.MappingRule
	Tiers       map[string]retention.TierConfig
	Files       []pruner.SnapshotFile
	Apply       bool
	Force       bool
}

func buildPlan(params planBuildParams) plan.SnapshotPlanOutput {
	return plan.BuildSnapshotPlan(toPlanBuildParams(params))
}

func toPlanBuildParams(params planBuildParams) plan.BuildSnapshotPlanParams {
	return plan.BuildSnapshotPlanParams{
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

func applyPlan(p plan.SnapshotPlanOutput, obsRoot, archiveDir string, allowSymlink bool) error {
	_, err := plan.ApplySnapshotPlan(plan.SnapshotPlanApplyInput{
		Entries:          toPlanEntries(p.Files),
		ObservationsRoot: obsRoot,
		ArchiveDir:       archiveDir,
		AllowSymlink:     allowSymlink,
	})
	if err != nil {
		return fmt.Errorf("applying snapshot lifecycle plan: %w", err)
	}
	return nil
}

func toPlanEntries(entries []plan.SnapshotPlanFile) []plan.PlanEntry {
	out := make([]plan.PlanEntry, len(entries))
	for i, entry := range entries {
		out[i] = plan.PlanEntry{
			RelPath: entry.RelPath,
			Action:  entry.Action,
		}
	}
	return out
}
