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

// planBuildParams holds all inputs for buildPlan (pure, testable).
type planBuildParams struct {
	Now         time.Time
	ObsRoot     string
	DefaultTier string
	TierRules   []retention.Rule
	Tiers       map[string]retention.Tier
	Files       []appcontracts.SnapshotFile
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
		DefaultTier:      params.DefaultTier,
		Tiers:            params.Tiers,
		Files:            toSnapshotFiles(params.Files),
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
			AssetID:    f.AssetID,
			AssetType:  f.AssetType,
		}
	}
	return out
}
