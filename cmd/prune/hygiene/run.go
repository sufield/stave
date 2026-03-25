package hygiene

import (
	"context"
	"io"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	pruneretention "github.com/sufield/stave/cmd/prune/retention"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	hygieneapp "github.com/sufield/stave/internal/app/hygiene"
	"github.com/sufield/stave/internal/cli/ui"
	staveversion "github.com/sufield/stave/internal/version"
	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/risk"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
	"github.com/sufield/stave/pkg/alpha/domain/retention"
)

// --- Config ---

// config defines the resolved parameters for the hygiene report.
type config struct {
	ControlsDir       string
	ObservationsDir   string
	ArchiveDir        string
	MaxUnsafeDuration time.Duration
	DueSoon           time.Duration
	Lookback          time.Duration
	OlderThan         time.Duration
	RetentionTier     string
	KeepMin           int
	Now               time.Time
	Format            ui.OutputFormat
	Quiet             bool
	Stdout            io.Writer

	Filter UpcomingFilter
}

// UpcomingFilter holds criteria to narrow down the risk assessment section.
type UpcomingFilter struct {
	ControlIDs   []kernel.ControlID
	AssetTypes   []kernel.AssetType
	Statuses     []risk.ThresholdStatus
	DueWithin    time.Duration
	DueWithinRaw string
}

// DueWithinPtr returns a *time.Duration for the domain layer (nil if unset).
func (f UpcomingFilter) DueWithinPtr() *time.Duration {
	if f.DueWithin <= 0 {
		return nil
	}
	d := f.DueWithin
	return &d
}

// --- Runner ---

// runner orchestrates the multi-domain hygiene report.
type runner struct {
	LoadAssets      compose.AssetLoaderFunc
	NewObsRepo      compose.ObsRepoFactory
	NewSnapshotRepo compose.SnapshotRepoFactory
}

// Run executes the hygiene analysis and renders the report.
func (r *runner) Run(ctx context.Context, cfg config) error {
	loaded, err := r.LoadAssets(ctx, cfg.ObservationsDir, cfg.ControlsDir)
	if err != nil {
		return err
	}

	obsRepo, err := r.NewObsRepo()
	if err != nil {
		return err
	}
	archiveSnapshots, err := loadSnapshotsIfDirExists(ctx, obsRepo, cfg.ArchiveDir)
	if err != nil {
		return err
	}

	files, err := pruneretention.ListObservationSnapshotFiles(ctx, r.NewSnapshotRepo, cfg.ObservationsDir)
	if err != nil {
		return err
	}

	previousNow := cfg.Now.Add(-cfg.Lookback)
	snapshotStats := buildSnapshotStats(cfg, loaded.Snapshots, archiveSnapshots, files)
	currentRisk, trend := computeRiskTrend(cfg, previousNow, loaded.Controls, loaded.Snapshots)

	reportReq := appcontracts.ReportRequest{
		Context: appcontracts.ReportContext{
			Now:         cfg.Now,
			PreviousNow: previousNow,
			Lookback:    cfg.Lookback,
			DueSoon:     cfg.DueSoon,
		},
		Snapshots: snapshotStats,
		Risks:     currentRisk,
		Trends:    trend,
	}
	jsonOut := hygieneapp.Output{
		GeneratedAt:      cfg.Now,
		LookbackStart:    previousNow,
		LookbackDuration: kernel.FormatDuration(cfg.Lookback),
		DueSoonThreshold: kernel.FormatDuration(cfg.DueSoon),
		Filters: hygieneapp.HygieneFilters{
			ControlIDs: cfg.Filter.ControlIDs,
			AssetTypes: cfg.Filter.AssetTypes,
			Statuses:   cfg.Filter.Statuses,
			DueWithin:  cfg.Filter.DueWithinRaw,
		},
		SnapshotStats: snapshotStats,
		RiskStats:     currentRisk,
		Trend:         trend,
	}

	if cfg.Quiet {
		return nil
	}
	return writeHygieneOutput(cfg.Format, reportReq, jsonOut, cfg.Stdout)
}

// --- Internal Helpers ---

func buildSnapshotStats(
	cfg config,
	activeSnapshots []asset.Snapshot,
	archiveSnapshots []asset.Snapshot,
	files []appcontracts.SnapshotFile,
) appcontracts.SnapshotStats {
	pruneCandidates := pruneretention.PlanPrune(files, retention.Criteria{
		Now:       cfg.Now,
		OlderThan: cfg.OlderThan,
		KeepMin:   cfg.KeepMin,
	})
	return appcontracts.SnapshotStats{
		Active:            len(activeSnapshots),
		Archived:          len(archiveSnapshots),
		PruneCandidates:   len(pruneCandidates),
		RetentionTier:     cfg.RetentionTier,
		RetentionDuration: cfg.OlderThan,
		KeepMin:           cfg.KeepMin,
	}
}

func computeRiskTrend(
	cfg config,
	previousNow time.Time,
	controls []policy.ControlDefinition,
	activeSnapshots []asset.Snapshot,
) (appcontracts.RiskStats, []evaluation.TrendMetric) {
	riskOpts := buildRiskOptions(cfg)

	svc := &hygieneapp.Service{}
	currentRisk := svc.ComputeRisk(controls, activeSnapshots, riskOpts)

	previousSnapshots := filterSnapshotsBefore(activeSnapshots, previousNow)
	previousOpts := riskOpts
	previousOpts.Now = previousNow
	previousRisk := svc.ComputeRisk(controls, previousSnapshots, previousOpts)

	trend := hygieneapp.CalculateTrend(currentRisk, previousRisk)
	return currentRisk, trend
}

func buildRiskOptions(cfg config) hygieneapp.RiskOptions {
	return hygieneapp.RiskOptions{
		GlobalMaxUnsafeDuration: cfg.MaxUnsafeDuration,
		Now:                     cfg.Now,
		DueSoonThreshold:        cfg.DueSoon,
		StaveVersion:            staveversion.String,
		ControlIDs:              cfg.Filter.ControlIDs,
		AssetTypes:              cfg.Filter.AssetTypes,
		Statuses:                cfg.Filter.Statuses,
		DueWithin:               cfg.Filter.DueWithinPtr(),
		PredicateParser:         ctlyaml.ParsePredicate,
	}
}
