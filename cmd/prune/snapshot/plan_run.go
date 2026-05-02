package snapshot

import (
	"context"
	"fmt"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/internal/adapters/pruner"
	appconfig "github.com/sufield/stave/internal/app/config"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/retention"
)

// listPlanFiles enumerates every snapshot file under observationsRoot.
// No exclude-dir handling is required: the plan command is read-only
// and never moves files into a sibling archive directory the walk
// would need to skip.
func listPlanFiles(ctx context.Context, newSnapshotRepo compose.SnapshotRepoFactory, observationsRoot string) ([]appcontracts.SnapshotFile, error) {
	loader, err := newSnapshotRepo()
	if err != nil {
		return nil, fmt.Errorf("create observation loader: %w", err)
	}
	return listSnapshotFilesRecursive(ctx, loader, observationsRoot, nil)
}

// listSnapshotFilesRecursive identifies snapshot files by traversing the directory tree.
// It requires an explicit SnapshotReader to avoid reliance on global providers.
func listSnapshotFilesRecursive(ctx context.Context, loader appcontracts.SnapshotReader, dir string, excludeDirs []string) ([]appcontracts.SnapshotFile, error) {
	files, err := pruner.ListSnapshotFilesRecursiveWithLoader(ctx, dir, excludeDirs, loader)
	if err != nil {
		return nil, fmt.Errorf("listing snapshots in %q: %w", dir, err)
	}
	return files, nil
}

func resolvePlanRetentionConfig(eval *appconfig.GovernanceResolver) (map[string]retention.Tier, []retention.Rule, string, error) {
	cfg, _, err := projconfig.FindProjectConfigWithPath("")
	if err != nil {
		return nil, nil, "", fmt.Errorf("load project config: %w", err)
	}
	defaultTier := eval.RetentionTier()
	var tiers map[string]retention.Tier
	var tierRules []retention.Rule
	if cfg != nil {
		tiers = cfg.RetentionTiers
		tierRules = cfg.ObservationTierMapping
	}
	if tiers == nil {
		tiers = map[string]retention.Tier{
			appconfig.DefaultRetentionTier: {
				OlderThan: appconfig.DefaultSnapshotRetention,
				KeepMin:   appconfig.DefaultTierKeepMin,
			},
		}
	}
	return tiers, tierRules, defaultTier, nil
}
