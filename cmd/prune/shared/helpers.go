package pruneshared

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	appconfig "github.com/sufield/stave/internal/app/config"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/retention"
	"github.com/sufield/stave/internal/pkg/timeutil"
	"github.com/sufield/stave/internal/pruner"
	"github.com/sufield/stave/internal/pruner/report"
)

// CleanupPlan holds the fields shared by delete and archive execution plans.
type CleanupPlan struct {
	Now             time.Time
	Action          report.CleanupAction
	DryRun          bool
	Quiet           bool
	Format          ui.OutputFormat
	ObservationsDir string
	Tier            string
	OlderThan       time.Duration
	KeepMin         int
	AllFiles        []pruner.SnapshotFile
	CandidateFiles  []pruner.SnapshotFile
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
	Action    report.CleanupAction
}

// ListObservationSnapshotFiles lists snapshot files from a flat observations directory.
func ListObservationSnapshotFiles(ctx context.Context, observationsDir string) ([]pruner.SnapshotFile, error) {
	loader, err := compose.ActiveProvider().NewSnapshotRepo()
	if err != nil {
		return nil, fmt.Errorf("create observation loader: %w", err)
	}
	files, err := pruner.ListSnapshotFilesFlatWithLoader(ctx, observationsDir, loader)
	if err != nil {
		return nil, fmt.Errorf("listing snapshots in %q: %w", observationsDir, err)
	}
	return files, nil
}

// PlanPrune determines which snapshot files should be pruned based on the given criteria.
func PlanPrune(files []pruner.SnapshotFile, criteria retention.Criteria) []pruner.SnapshotFile {
	items := make([]retention.Candidate, len(files))
	for i, sf := range files {
		items[i] = retention.Candidate{
			Index:      i,
			CapturedAt: sf.CapturedAt,
		}
	}
	selected := retention.PlanPrune(items, criteria)
	out := make([]pruner.SnapshotFile, 0, len(selected))
	for _, item := range selected {
		if item.Index >= 0 && item.Index < len(files) {
			out = append(out, files[item.Index])
		}
	}
	return out
}

// ValidateRetentionTier normalizes and validates a retention tier name.
func ValidateRetentionTier(rawTier string) (string, error) {
	tier := appconfig.NormalizeTier(rawTier)
	if tier == "" {
		return "", fmt.Errorf("--retention-tier cannot be empty")
	}
	eval := projconfig.Global()
	if !eval.HasConfiguredTier(tier) {
		if cfg, ok := projconfig.FindProjectConfig(); ok && len(cfg.RetentionTiers) > 0 {
			return "", fmt.Errorf("unknown --retention-tier %q (configured tiers: %s)",
				tier, strings.Join(appconfig.SortedTierNames(cfg.RetentionTiers), ", "))
		}
	}
	return tier, nil
}

// ResolveOlderThan resolves the --older-than duration from the flag value or tier config.
// If flagChanged is false, the tier-specific retention from project config is used instead.
func ResolveOlderThan(flagValue string, flagChanged bool, tier string) (time.Duration, error) {
	raw := flagValue
	if !flagChanged {
		raw = projconfig.Global().SnapshotRetentionForTier(tier)
	}
	dur, err := timeutil.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid --older-than %q (use format: 14d, 720h, or 1d12h)", raw)
	}
	return dur, nil
}
