package hygiene

import (
	"context"
	"io"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	pruneshared "github.com/sufield/stave/cmd/prune/shared"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	hygieneapp "github.com/sufield/stave/internal/app/hygiene"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/pkg/timeutil"
	staveversion "github.com/sufield/stave/internal/version"
	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/risk"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
	"github.com/sufield/stave/pkg/alpha/domain/retention"
)

// --- Config ---

// Config defines the resolved parameters for the hygiene report.
type Config struct {
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
	Statuses     []risk.Status
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

// Runner orchestrates the multi-domain hygiene report.
type Runner struct {
	Provider *compose.Provider
}

// Run executes the hygiene analysis and renders the report.
func (r *Runner) Run(ctx context.Context, cfg Config) error {
	loaded, err := r.Provider.LoadAssets(ctx, cfg.ObservationsDir, cfg.ControlsDir)
	if err != nil {
		return err
	}

	obsRepo, err := r.Provider.NewObservationRepo()
	if err != nil {
		return err
	}
	archiveSnapshots, err := loadSnapshotsIfDirExists(ctx, obsRepo, cfg.ArchiveDir)
	if err != nil {
		return err
	}

	files, err := pruneshared.ListObservationSnapshotFiles(ctx, r.Provider, cfg.ObservationsDir)
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
		LookbackDuration: timeutil.FormatDuration(cfg.Lookback),
		DueSoonThreshold: timeutil.FormatDuration(cfg.DueSoon),
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
	cfg Config,
	activeSnapshots []asset.Snapshot,
	archiveSnapshots []asset.Snapshot,
	files []appcontracts.SnapshotFile,
) appcontracts.SnapshotStats {
	pruneCandidates := pruneshared.PlanPrune(files, retention.Criteria{
		Now:       cfg.Now,
		OlderThan: cfg.OlderThan,
		KeepMin:   cfg.KeepMin,
	})
	return appcontracts.NewSnapshotStats(
		len(activeSnapshots),
		len(archiveSnapshots),
		len(pruneCandidates),
		cfg.KeepMin,
		cfg.RetentionTier,
		cfg.OlderThan,
	)
}

func computeRiskTrend(
	cfg Config,
	previousNow time.Time,
	controls []policy.ControlDefinition,
	activeSnapshots []asset.Snapshot,
) (appcontracts.RiskStats, []evaluation.TrendMetric) {
	riskOpts := buildRiskOptions(cfg)

	svc := hygieneapp.NewService()
	currentRisk := svc.ComputeRisk(controls, activeSnapshots, riskOpts)

	previousSnapshots := filterSnapshotsBefore(activeSnapshots, previousNow)
	previousOpts := riskOpts
	previousOpts.Now = previousNow
	previousRisk := svc.ComputeRisk(controls, previousSnapshots, previousOpts)

	trend := hygieneapp.CalculateTrend(currentRisk, previousRisk)
	return currentRisk, trend
}

func buildRiskOptions(cfg Config) hygieneapp.RiskOptions {
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
