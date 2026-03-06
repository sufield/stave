package archive

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/pkg/timeutil"
	"github.com/sufield/stave/internal/pruner"
)

type snapshotFile = pruner.SnapshotFile
type PruningCriteria = pruner.Criteria

func listObservationSnapshotFiles(observationsDir string) ([]snapshotFile, error) {
	loader, err := cmdutil.NewSnapshotObservationRepository()
	if err != nil {
		return nil, fmt.Errorf("create observation loader: %w", err)
	}
	files, err := pruner.ListSnapshotFilesFlatWithLoader(observationsDir, loader)
	if err != nil {
		return nil, err
	}
	return files, nil
}

func planPrune(files []snapshotFile, criteria PruningCriteria) []snapshotFile {
	items := make([]pruner.Candidate, 0, len(files))
	for i, sf := range files {
		items = append(items, pruner.Candidate{
			Index:      i,
			CapturedAt: sf.CapturedAt,
		})
	}
	selected := pruner.PlanPrune(items, criteria)
	out := make([]snapshotFile, 0, len(selected))
	for _, item := range selected {
		if item.Index < 0 || item.Index >= len(files) {
			continue
		}
		out = append(out, files[item.Index])
	}
	return out
}

func validateRetentionTier(rawTier string) (string, error) {
	tier := cmdutil.NormalizeRetentionTier(rawTier)
	if tier == "" {
		return "", fmt.Errorf("--retention-tier cannot be empty")
	}
	if !cmdutil.HasConfiguredRetentionTier(tier) {
		if cfg, ok := cmdutil.FindProjectConfig(); ok && len(cfg.RetentionTiers) > 0 {
			return "", fmt.Errorf("unknown --retention-tier %q (configured tiers: %s)", tier, strings.Join(cmdutil.SortedRetentionTierNames(cfg.RetentionTiers), ", "))
		}
	}
	return tier, nil
}

func resolveCleanupOlderThan(cmd *cobra.Command, raw, tier string) (time.Duration, error) {
	olderThanRaw := raw
	if !cmd.Flags().Changed("older-than") {
		olderThanRaw = cmdutil.ResolveSnapshotRetentionForTier(tier)
	}
	olderThan, err := timeutil.ParseDuration(olderThanRaw)
	if err != nil {
		return 0, fmt.Errorf("invalid --older-than %q (use format: 14d, 720h, or 1d12h)", olderThanRaw)
	}
	return olderThan, nil
}
