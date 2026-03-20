package snapshot

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/internal/adapters/pruner"
	appconfig "github.com/sufield/stave/internal/app/config"
	"github.com/sufield/stave/pkg/alpha/domain/retention"
)

func listPlanFiles(ctx context.Context, p *compose.Provider, observationsRoot, archiveDir string) ([]pruner.SnapshotFile, error) {
	loader, err := p.NewSnapshotRepo()
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

func resolvePlanRetentionConfig() (map[string]retention.TierConfig, []retention.MappingRule, string, error) {
	cfg, _, err := projconfig.FindProjectConfigWithPath("")
	if err != nil {
		return nil, nil, "", fmt.Errorf("load project config: %w", err)
	}
	defaultTier := projconfig.Global().RetentionTier()
	var tiers map[string]retention.TierConfig
	var tierRules []retention.MappingRule
	if cfg != nil {
		tiers = cfg.RetentionTiers
		tierRules = cfg.ObservationTierMapping
	}
	if tiers == nil {
		tiers = map[string]retention.TierConfig{
			appconfig.DefaultRetentionTier: {
				OlderThan: appconfig.DefaultSnapshotRetention,
				KeepMin:   appconfig.DefaultTierKeepMin,
			},
		}
	}
	return tiers, tierRules, defaultTier, nil
}
