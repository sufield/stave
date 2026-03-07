package snapshot

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/pruner"
)

func runPlan(cmd *cobra.Command, _ []string) error {
	runInput, err := preparePlanRunInput()
	if err != nil {
		return err
	}
	files, err := listPlanFiles(runInput.observationsRoot, runInput.archiveDir)
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
		Apply:       planApply,
		Force:       cmdutil.ForceEnabled(cmd),
	})
	if err := writePlanOutput(cmd, plan); err != nil {
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
	tiers            cmdutil.RetentionTiersMap
	tierRules        []cmdutil.TierMappingRule
}

func preparePlanRunInput() (planRunInput, error) {
	planObservationsRoot = fsutil.CleanUserPath(planObservationsRoot)
	if planArchiveDir != "" {
		planArchiveDir = fsutil.CleanUserPath(planArchiveDir)
	}

	now, err := cmdutil.ResolveNow(planNow)
	if err != nil {
		return planRunInput{}, err
	}
	tiers, tierRules, defaultTier := resolvePlanRetentionConfig()
	return planRunInput{
		observationsRoot: planObservationsRoot,
		archiveDir:       planArchiveDir,
		now:              now,
		defaultTier:      defaultTier,
		tiers:            tiers,
		tierRules:        tierRules,
	}, nil
}

func resolvePlanRetentionConfig() (cmdutil.RetentionTiersMap, []cmdutil.TierMappingRule, string) {
	cfg, _, _ := cmdutil.FindProjectConfigWithPath()
	defaultTier := cmdutil.ResolveRetentionTierDefault()
	var tiers cmdutil.RetentionTiersMap
	var tierRules []cmdutil.TierMappingRule
	if cfg != nil {
		tiers = cfg.RetentionTiers
		tierRules = cfg.ObservationTierMapping
	}
	if tiers == nil {
		tiers = cmdutil.RetentionTiersMap{
			cmdutil.DefaultRetentionTier: {
				OlderThan: cmdutil.DefaultSnapshotRetention,
				KeepMin:   cmdutil.DefaultTierKeepMin,
			},
		}
	}
	return tiers, tierRules, defaultTier
}

func listPlanFiles(observationsRoot, archiveDir string) ([]snapshotFile, error) {
	excludeDirs := make([]string, 0, 1)
	if archiveDir != "" {
		if abs, err := filepath.Abs(archiveDir); err == nil {
			excludeDirs = append(excludeDirs, abs)
		}
	}
	return listObservationSnapshotFilesRecursive(observationsRoot, excludeDirs)
}

func writePlanOutput(cmd *cobra.Command, plan planOutput) error {
	format, err := cmdutil.ResolveFormatValue(cmd, planFormat)
	if err != nil {
		return err
	}
	if cmdutil.QuietEnabled(cmd) {
		return nil
	}
	w := cmd.OutOrStdout()
	if format.IsJSON() {
		if err := writeJSON(w, plan); err != nil {
			return fmt.Errorf("write plan output: %w", err)
		}
		return nil
	}
	if err := pruner.RenderSnapshotPlanText(w, plan); err != nil {
		return fmt.Errorf("write plan output: %w", err)
	}
	return nil
}
