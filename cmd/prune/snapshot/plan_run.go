package snapshot

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	appconfig "github.com/sufield/stave/internal/app/config"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/retention"
)

func listPlanFiles(ctx context.Context, newSnapshotRepo compose.SnapshotRepoFactory, observationsRoot, archiveDir string) ([]appcontracts.SnapshotFile, error) {
	loader, err := newSnapshotRepo()
	if err != nil {
		return nil, fmt.Errorf("create observation loader: %w", err)
	}
	excludeDirs := make([]string, 0, 1)
	if archiveDir != "" {
		if abs, err := filepath.Abs(archiveDir); err == nil {
			excludeDirs = append(excludeDirs, abs)
		}
	}
	return listSnapshotFilesRecursive(ctx, loader, observationsRoot, excludeDirs)
}

func resolvePlanRetentionConfig(eval *appconfig.Evaluator) (map[string]retention.Tier, []retention.Rule, string, error) {
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
