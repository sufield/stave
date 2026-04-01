package snapshot

import (
	"fmt"
	"time"

	appconfig "github.com/sufield/stave/internal/app/config"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/retention"
	snapshotdomain "github.com/sufield/stave/internal/core/snapplan"
)

// ApplyParams bundles the execution details for applying a snapshot plan,
// preventing accidental swaps of the two path strings and eliminating the
// opaque trailing boolean.
type ApplyParams struct {
	Entries         []snapshotdomain.PlanEntry
	ObservationsDir string
	ArchiveDir      string
	AllowSymlink    bool
}

// PlanApplyFunc applies a computed plan against the filesystem.
// Injected by the cmd layer to keep the app free of adapter imports.
type PlanApplyFunc func(params ApplyParams) error

// planBuildParams holds all inputs for buildPlan (pure, testable).
type planBuildParams struct {
	Now         time.Time
	ObsRoot     string
	ArchiveDir  string
	DefaultTier string
	TierRules   []retention.Rule
	Tiers       map[string]retention.Tier
	Files       []appcontracts.SnapshotFile
	Apply       bool
	Force       bool
}

func buildPlan(params planBuildParams) (*snapshotdomain.PlanOutput, error) {
	defaultOlderThan, err := kernel.ParseDuration(appconfig.DefaultSnapshotRetention)
	if err != nil {
		return nil, fmt.Errorf("parse default retention: %w", err)
	}

	resolver := snapshotdomain.TierResolverFunc(func(relPath string) string {
		return appconfig.ResolveTierForPath(relPath, params.TierRules, params.DefaultTier)
	})

	return snapshotdomain.BuildPlan(snapshotdomain.BuildPlanParams{
		Now:              params.Now,
		ObsRoot:          params.ObsRoot,
		ArchiveDir:       params.ArchiveDir,
		DefaultTier:      params.DefaultTier,
		Tiers:            params.Tiers,
		Files:            toSnapshotFiles(params.Files),
		Apply:            params.Apply,
		Force:            params.Force,
		DefaultOlderThan: defaultOlderThan,
		DefaultKeepMin:   appconfig.DefaultTierKeepMin,
		TierResolver:     resolver,
	})
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
