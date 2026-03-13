package pruneshared

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/pkg/timeutil"
	"github.com/sufield/stave/internal/pruner"
)

// CleanupPlan holds the fields shared by delete and archive execution plans.
type CleanupPlan struct {
	Now             time.Time
	Action          pruner.CleanupAction
	DryRun          bool
	Quiet           bool
	Format          ui.OutputFormat
	ObservationsDir string
	Tier            string
	OlderThan       time.Duration
	KeepMin         int
	AllFiles        []SnapshotFile
	CandidateFiles  []SnapshotFile
}

// CleanupRunInput holds the fields shared by delete and archive resolved inputs.
type CleanupRunInput struct {
	ObsDir    string
	Tier      string
	OlderThan time.Duration
	Now       time.Time
	Format    ui.OutputFormat
	KeepMin   int
	DryRun    bool
	Quiet     bool
	Action    pruner.CleanupAction
}

// SnapshotFile is an alias for pruner.SnapshotFile.
type SnapshotFile = pruner.SnapshotFile

// PruningCriteria is an alias for pruner.Criteria.
type PruningCriteria = pruner.Criteria

// ListObservationSnapshotFiles lists snapshot files from a flat observations directory.
func ListObservationSnapshotFiles(ctx context.Context, observationsDir string) ([]SnapshotFile, error) {
	loader, err := compose.ActiveProvider().NewSnapshotRepo()
	if err != nil {
		return nil, fmt.Errorf("create observation loader: %w", err)
	}
	files, err := pruner.ListSnapshotFilesFlatWithLoader(ctx, observationsDir, loader)
	if err != nil {
		return nil, err
	}
	return files, nil
}

// PlanPrune determines which snapshot files should be pruned based on the given criteria.
func PlanPrune(files []SnapshotFile, criteria PruningCriteria) []SnapshotFile {
	items := make([]pruner.Candidate, 0, len(files))
	for i, sf := range files {
		items = append(items, pruner.Candidate{
			Index:      i,
			CapturedAt: sf.CapturedAt,
		})
	}
	selected := pruner.PlanPrune(items, criteria)
	out := make([]SnapshotFile, 0, len(selected))
	for _, item := range selected {
		if item.Index < 0 || item.Index >= len(files) {
			continue
		}
		out = append(out, files[item.Index])
	}
	return out
}

// ValidateRetentionTier normalizes and validates a retention tier name.
func ValidateRetentionTier(rawTier string) (string, error) {
	tier := projconfig.NormalizeTier(rawTier)
	if tier == "" {
		return "", fmt.Errorf("--retention-tier cannot be empty")
	}
	if !projconfig.Global().HasConfiguredTier(tier) {
		if cfg, ok := projconfig.FindProjectConfig(); ok && len(cfg.RetentionTiers) > 0 {
			return "", fmt.Errorf("unknown --retention-tier %q (configured tiers: %s)", tier, strings.Join(projconfig.SortedTierNames(cfg.RetentionTiers), ", "))
		}
	}
	return tier, nil
}

// ResolveOlderThan resolves the --older-than duration from the flag or tier config.
func ResolveOlderThan(cmd *cobra.Command, raw, tier string) (time.Duration, error) {
	olderThanRaw := raw
	if !cmd.Flags().Changed("older-than") {
		olderThanRaw = projconfig.Global().SnapshotRetentionForTier(tier)
	}
	olderThan, err := timeutil.ParseDuration(olderThanRaw)
	if err != nil {
		return 0, fmt.Errorf("invalid --older-than %q (use format: 14d, 720h, or 1d12h)", olderThanRaw)
	}
	return olderThan, nil
}
