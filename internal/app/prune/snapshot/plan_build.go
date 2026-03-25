package snapshot

import (
	"fmt"
	"time"

	appconfig "github.com/sufield/stave/internal/app/config"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/retention"
	snapshotdomain "github.com/sufield/stave/pkg/alpha/domain/snapshot"
)

// PlanApplyFunc applies a computed plan against the filesystem.
// Injected by the cmd layer to keep the app free of adapter imports.
type PlanApplyFunc func(entries []snapshotdomain.PlanEntry, obsRoot, archiveDir string, allowSymlink bool) error

// planBuildParams holds all inputs for buildPlan (pure, testable).
type planBuildParams struct {
	Now         time.Time
	ObsRoot     string
	ArchiveDir  string
	DefaultTier string
	TierRules   []retention.MappingRule
	Tiers       map[string]retention.TierConfig
	Files       []appcontracts.SnapshotFile
	Apply       bool
	Force       bool
}

func buildPlan(params planBuildParams) snapshotdomain.PlanOutput {
	return snapshotdomain.BuildPlan(snapshotdomain.BuildPlanParams{
		Now:                params.Now,
		ObsRoot:            params.ObsRoot,
		ArchiveDir:         params.ArchiveDir,
		DefaultTier:        params.DefaultTier,
		TierRules:          params.TierRules,
		Tiers:              params.Tiers,
		Files:              toSnapshotFiles(params.Files),
		Apply:              params.Apply,
		Force:              params.Force,
		DefaultOlderThan:   appconfig.DefaultSnapshotRetention,
		DefaultKeepMin:     appconfig.DefaultTierKeepMin,
		ParseDuration:      kernel.ParseDuration,
		ResolveTierForPath: appconfig.ResolveTierForPath,
	})
}

func applyPlan(applyFn PlanApplyFunc, p snapshotdomain.PlanOutput, obsRoot, archiveDir string, allowSymlink bool) error {
	entries := toPlanEntries(p.Files)
	if err := applyFn(entries, obsRoot, archiveDir, allowSymlink); err != nil {
		return fmt.Errorf("applying snapshot lifecycle plan: %w", err)
	}
	return nil
}

func toSnapshotFiles(files []appcontracts.SnapshotFile) []snapshotdomain.File {
	out := make([]snapshotdomain.File, len(files))
	for i, f := range files {
		out[i] = snapshotdomain.File{
			Path:       f.Path,
			RelPath:    f.RelPath,
			Name:       f.Name,
			CapturedAt: f.CapturedAt,
		}
	}
	return out
}

func toPlanEntries(files []snapshotdomain.PlanFile) []snapshotdomain.PlanEntry {
	out := make([]snapshotdomain.PlanEntry, len(files))
	for i, f := range files {
		out[i] = snapshotdomain.PlanEntry{
			RelPath: f.RelPath,
			Action:  f.Action,
		}
	}
	return out
}
