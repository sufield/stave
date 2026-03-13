package snapshot

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/internal/pkg/jsonutil"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/pruner"
)

func runPlan(cmd *cobra.Command, flags *planFlagsType) error {
	runInput, err := preparePlanRunInput(flags)
	if err != nil {
		return err
	}
	files, err := listPlanFiles(cmd.Context(), runInput.observationsRoot, runInput.archiveDir)
	if err != nil {
		return err
	}

	plan := buildPlan(planBuildParams{
		Now:         runInput.now,
		ObsRoot:     runInput.observationsRoot,
		ArchiveDir:  runInput.archiveDir,
		DefaultTier: runInput.defaultTier,
		TierRules:   runInput.tierRules,
		Tiers:       runInput.tiers,
		Files:       files,
		Apply:       flags.apply,
		Force:       cmdutil.ForceEnabled(cmd),
	})
	if err := writePlanOutput(cmd, plan, flags.format); err != nil {
		return err
	}
	if plan.Applied {
		return applyPlan(plan, runInput.observationsRoot, runInput.archiveDir, cmdutil.AllowSymlinkOutEnabled(cmd))
	}
	return nil
}

type planRunInput struct {
	observationsRoot string
	archiveDir       string
	now              time.Time
	defaultTier      string
	tiers            projconfig.RetentionTiersMap
	tierRules        []projconfig.TierMappingRule
}

func preparePlanRunInput(flags *planFlagsType) (planRunInput, error) {
	obsRoot := fsutil.CleanUserPath(flags.observationsRoot)
	var archiveDir string
	if flags.archiveDir != "" {
		archiveDir = fsutil.CleanUserPath(flags.archiveDir)
	}

	now, err := compose.ResolveNow(flags.now)
	if err != nil {
		return planRunInput{}, err
	}
	tiers, tierRules, defaultTier := resolvePlanRetentionConfig()
	return planRunInput{
		observationsRoot: obsRoot,
		archiveDir:       archiveDir,
		now:              now,
		defaultTier:      defaultTier,
		tiers:            tiers,
		tierRules:        tierRules,
	}, nil
}

func resolvePlanRetentionConfig() (projconfig.RetentionTiersMap, []projconfig.TierMappingRule, string) {
	cfg, _, _ := projconfig.FindProjectConfigWithPath("")
	defaultTier := projconfig.ResolveRetentionTierDefault()
	var tiers projconfig.RetentionTiersMap
	var tierRules []projconfig.TierMappingRule
	if cfg != nil {
		tiers = cfg.RetentionTiers
		tierRules = cfg.ObservationTierMapping
	}
	if tiers == nil {
		tiers = projconfig.RetentionTiersMap{
			projconfig.DefaultRetentionTier: {
				OlderThan: projconfig.DefaultSnapshotRetention,
				KeepMin:   projconfig.DefaultTierKeepMin,
			},
		}
	}
	return tiers, tierRules, defaultTier
}

func listPlanFiles(ctx context.Context, observationsRoot, archiveDir string) ([]snapshotFile, error) {
	excludeDirs := make([]string, 0, 1)
	if archiveDir != "" {
		if abs, err := filepath.Abs(archiveDir); err == nil {
			excludeDirs = append(excludeDirs, abs)
		}
	}
	return listObservationSnapshotFilesRecursive(ctx, observationsRoot, excludeDirs)
}

func writePlanOutput(cmd *cobra.Command, plan planOutput, rawFormat string) error {
	format, err := compose.ResolveFormatValue(cmd, rawFormat)
	if err != nil {
		return err
	}
	if cmdutil.QuietEnabled(cmd) {
		return nil
	}
	w := cmd.OutOrStdout()
	if format.IsJSON() {
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
