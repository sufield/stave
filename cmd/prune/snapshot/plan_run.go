package snapshot

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/retention"
	"github.com/sufield/stave/internal/pkg/jsonutil"
	"github.com/sufield/stave/internal/pruner"
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
type PlanRunner struct{}

// Run executes the multi-tier planning workflow.
func (r *PlanRunner) Run(ctx context.Context, cfg PlanConfig) error {
	files, err := listPlanFiles(ctx, cfg.ObservationsRoot, cfg.ArchiveDir)
	if err != nil {
		return err
	}

	tiers, tierRules, defaultTier := resolvePlanRetentionConfig()

	plan := buildPlan(planBuildParams{
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

	if err := r.writePlanOutput(cfg, plan); err != nil {
		return err
	}
	if plan.Applied {
		return applyPlan(plan, cfg.ObservationsRoot, cfg.ArchiveDir, cfg.AllowSymlink)
	}
	return nil
}

func (r *PlanRunner) writePlanOutput(cfg PlanConfig, plan pruner.SnapshotPlanOutput) error {
	if cfg.Quiet {
		return nil
	}
	w := cfg.Stdout
	if cfg.Format.IsJSON() {
		if err := jsonutil.WriteIndented(w, plan); err != nil {
			return fmt.Errorf("write plan output: %w", err)
		}
		return nil
	}
	if err := pruner.RenderSnapshotPlanText(w, plan); err != nil {
		return fmt.Errorf("write plan output: %w", err)
	}
	return nil
}

// --- Helpers ---

func listPlanFiles(ctx context.Context, observationsRoot, archiveDir string) ([]pruner.SnapshotFile, error) {
	loader, err := compose.ActiveProvider().NewSnapshotRepo()
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
			projconfig.DefaultRetentionTier: {
				OlderThan: projconfig.DefaultSnapshotRetention,
				KeepMin:   projconfig.DefaultTierKeepMin,
			},
		}
	}
	return tiers, tierRules, defaultTier
}
