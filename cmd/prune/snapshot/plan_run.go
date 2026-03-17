package snapshot

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	appconfig "github.com/sufield/stave/internal/app/config"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/retention"
	"github.com/sufield/stave/internal/pkg/jsonutil"
	"github.com/sufield/stave/internal/pruner"
	"github.com/sufield/stave/internal/pruner/plan"
)

// PlanConfig defines the resolved parameters for multi-tier snapshot retention.
type PlanConfig struct {
	ObservationsRoot string
	ArchiveDir       string
	Now              time.Time
	Format           ui.OutputFormat
	Apply            bool
	Force            bool
	Quiet            bool
	AllowSymlink     bool
	Stdout           io.Writer
}

// PlanRunner orchestrates the recursive inspection and lifecycle execution.
type PlanRunner struct {
	Provider *compose.Provider
}

// Run executes the multi-tier planning workflow.
func (r *PlanRunner) Run(ctx context.Context, cfg PlanConfig) error {
	files, err := listPlanFiles(ctx, r.Provider, cfg.ObservationsRoot, cfg.ArchiveDir)
	if err != nil {
		return err
	}

	tiers, tierRules, defaultTier := resolvePlanRetentionConfig()

	p := buildPlan(planBuildParams{
		Now:         cfg.Now,
		ObsRoot:     cfg.ObservationsRoot,
		ArchiveDir:  cfg.ArchiveDir,
		DefaultTier: defaultTier,
		TierRules:   tierRules,
		Tiers:       tiers,
		Files:       files,
		Apply:       cfg.Apply,
		Force:       cfg.Force,
	})

	if err := r.writePlanOutput(cfg, p); err != nil {
		return err
	}
	if p.Applied {
		return applyPlan(p, cfg.ObservationsRoot, cfg.ArchiveDir, cfg.AllowSymlink)
	}
	return nil
}

func (r *PlanRunner) writePlanOutput(cfg PlanConfig, p plan.SnapshotPlanOutput) error {
	if cfg.Quiet {
		return nil
	}
	w := cfg.Stdout
	if cfg.Format.IsJSON() {
		if err := jsonutil.WriteIndented(w, p); err != nil {
			return fmt.Errorf("write plan output: %w", err)
		}
		return nil
	}
	if err := plan.RenderSnapshotPlanText(w, p); err != nil {
		return fmt.Errorf("write plan output: %w", err)
	}
	return nil
}

// --- Helpers ---

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

func resolvePlanRetentionConfig() (map[string]retention.TierConfig, []retention.MappingRule, string) {
	cfg, _, _ := projconfig.FindProjectConfigWithPath("")
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
	return tiers, tierRules, defaultTier
}
