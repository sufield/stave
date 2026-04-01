package retention

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/internal/adapters/pruner"
	appconfig "github.com/sufield/stave/internal/app/config"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/retention"
)

// CleanupPlan holds the fields shared by delete and archive execution plans.
type CleanupPlan struct {
	Now             time.Time
	Action          pruner.CleanupAction
	DryRun          bool
	Quiet           bool
	Format          appcontracts.OutputFormat
	ObservationsDir string
	Tier            string
	OlderThan       time.Duration
	KeepMin         int
	AllFiles        []appcontracts.SnapshotFile
	CandidateFiles  []appcontracts.SnapshotFile
}

// CleanupRunInput holds the fields shared by delete and archive resolved inputs.
type CleanupRunInput struct {
	ObsDir    string
	Tier      string
	OlderThan time.Duration
	Now       time.Time
	Format    appcontracts.OutputFormat
	KeepMin   int
	DryRun    bool
	Quiet     bool
	Action    pruner.CleanupAction
}

// ListObservationSnapshotFiles lists snapshot files from a flat observations directory.
func ListObservationSnapshotFiles(ctx context.Context, loader appcontracts.SnapshotReader, observationsDir string) ([]appcontracts.SnapshotFile, error) {
	files, err := pruner.ListSnapshotFilesFlatWithLoader(ctx, observationsDir, loader)
	if err != nil {
		return nil, fmt.Errorf("listing snapshots in %q: %w", observationsDir, err)
	}
	return files, nil
}

// PlanPrune determines which snapshot files should be pruned based on the given criteria.
func PlanPrune(files []appcontracts.SnapshotFile, criteria retention.Criteria) []appcontracts.SnapshotFile {
	items := make([]retention.Candidate, len(files))
	for i, sf := range files {
		items[i] = retention.Candidate{
			Index:      i,
			CapturedAt: sf.CapturedAt,
		}
	}
	slices.SortFunc(items, func(a, b retention.Candidate) int {
		return a.CapturedAt.Compare(b.CapturedAt)
	})
	selected := retention.PlanPrune(items, criteria)
	out := make([]appcontracts.SnapshotFile, 0, len(selected))
	for _, item := range selected {
		if item.Index >= 0 && item.Index < len(files) {
			out = append(out, files[item.Index])
		}
	}
	return out
}

// RawRetentionOpts holds the unresolved flag values common to prune and archive.
type RawRetentionOpts struct {
	OlderThan  string
	Tier       string
	NowRaw     string
	FormatFlag string
}

// ResolvedRetention holds the fully resolved retention parameters.
type ResolvedRetention struct {
	OlderThan     time.Duration
	RetentionTier string
	Now           time.Time
	Format        appcontracts.OutputFormat
}

// ResolveRetention transforms raw CLI flag values into fully resolved retention
// parameters. olderThanChanged and formatChanged indicate whether the respective
// flags were explicitly set by the user. isJSONMode indicates global JSON output mode.
// tierChanged indicates whether --retention-tier was explicitly set.
func ResolveRetention(raw RawRetentionOpts, eval *appconfig.Evaluator, olderThanChanged, tierChanged, formatChanged, isJSONMode bool) (ResolvedRetention, error) {
	olderThan := raw.OlderThan
	if !olderThanChanged {
		olderThan = eval.SnapshotRetention()
	}
	tier := raw.Tier
	if !tierChanged {
		tier = eval.RetentionTier()
	}

	validTier, err := ValidateRetentionTierWith(eval, tier)
	if err != nil {
		return ResolvedRetention{}, err
	}
	resolvedOlderThan, err := ResolveOlderThanWith(eval, olderThan, olderThanChanged, validTier)
	if err != nil {
		return ResolvedRetention{}, err
	}
	now, err := compose.ResolveNow(raw.NowRaw)
	if err != nil {
		return ResolvedRetention{}, err
	}
	format, err := compose.ResolveFormatValuePure(raw.FormatFlag, formatChanged, isJSONMode)
	if err != nil {
		return ResolvedRetention{}, err
	}

	return ResolvedRetention{
		OlderThan:     resolvedOlderThan,
		RetentionTier: validTier,
		Now:           now,
		Format:        format,
	}, nil
}

// ValidateRetentionTierWith normalizes and validates a retention tier name
// using the supplied evaluator instead of the global singleton.
func ValidateRetentionTierWith(eval *appconfig.Evaluator, rawTier string) (string, error) {
	tier := appconfig.NormalizeTier(rawTier)
	if tier == "" {
		return "", fmt.Errorf("--retention-tier cannot be empty")
	}
	if !eval.HasConfiguredTier(tier) {
		cfg, ok, cfgErr := projconfig.FindProjectConfig()
		if cfgErr != nil {
			return "", fmt.Errorf("load project config for tier validation: %w", cfgErr)
		}
		if ok && len(cfg.RetentionTiers) > 0 {
			return "", fmt.Errorf("unknown --retention-tier %q (configured tiers: %s)",
				tier, strings.Join(appconfig.SortedTierNames(cfg.RetentionTiers), ", "))
		}
	}
	return tier, nil
}

// ResolveOlderThanWith resolves the --older-than duration using the supplied evaluator.
func ResolveOlderThanWith(eval *appconfig.Evaluator, flagValue string, flagChanged bool, tier string) (time.Duration, error) {
	raw := flagValue
	if !flagChanged {
		raw = eval.SnapshotRetentionForTier(tier)
	}
	dur, err := kernel.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid --older-than %q (use format: 14d, 720h, or 1d12h)", raw)
	}
	return dur, nil
}
