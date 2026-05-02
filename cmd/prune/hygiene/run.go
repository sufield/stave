package hygiene

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	pruneretention "github.com/sufield/stave/cmd/prune/retention"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	hygieneapp "github.com/sufield/stave/internal/app/hygiene"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/core/retention"
	staveversion "github.com/sufield/stave/internal/version"
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
	Format            appcontracts.OutputFormat
	Quiet             bool
	Stdout            io.Writer

	Filter UpcomingFilter
}

// ShouldEmit reports whether RunHygiene / RunRisk should produce
// formatted output. Centralises the cfg.Quiet probe so the
// run-mode functions stop asking the field directly.
func (c config) ShouldEmit() bool {
	return !c.Quiet
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

// RunStatus generates only the snapshot summary section.
func (r *runner) RunStatus(ctx context.Context, cfg config) error {
	obsRepo, err := r.NewObsRepo()
	if err != nil {
		return err
	}

	activeSnapshots, err := loadSnapshotsIfDirExists(ctx, obsRepo, cfg.ObservationsDir)
	if err != nil {
		return err
	}
	archiveSnapshots, err := loadSnapshotsIfDirExists(ctx, obsRepo, cfg.ArchiveDir)
	if err != nil {
		return err
	}

	snapshotLoader, err := r.NewSnapshotRepo()
	if err != nil {
		return err
	}
	files, err := pruneretention.ListObservationSnapshotFiles(ctx, snapshotLoader, cfg.ObservationsDir)
	if err != nil {
		return err
	}

	stats := buildSnapshotStats(cfg, activeSnapshots, archiveSnapshots, files)

	if !cfg.ShouldEmit() {
		return nil
	}

	report := appcontracts.HygieneAssessment{
		AuditContext: appcontracts.AuditContext{Now: cfg.Now},
		Evidence:     stats,
	}
	jsonOut := hygieneapp.Output{
		GeneratedAt:     cfg.Now,
		SnapshotSummary: stats,
	}
	return writeHygieneOutput(cfg.Format, report, jsonOut, cfg.Stdout)
}

// RunRisk generates only the SLA posture and trend section.
func (r *runner) RunRisk(ctx context.Context, cfg config) error {
	loaded, err := r.LoadAssets(ctx, cfg.ObservationsDir, cfg.ControlsDir)
	if err != nil {
		return err
	}

	previousNow := cfg.Now.Add(-cfg.Lookback)
	currentRisk, trend, err := computeRiskTrend(ctx, cfg, previousNow, loaded.Controls, loaded.Snapshots)
	if err != nil {
		return err
	}

	if !cfg.ShouldEmit() {
		return nil
	}

	report := appcontracts.HygieneAssessment{
		AuditContext: appcontracts.AuditContext{
			Now:             cfg.Now,
			PreviousAuditAt: previousNow,
			LookbackWindow:  cfg.Lookback,
			SLAWarning:      cfg.DueSoon,
		},
		SLAPosture:      currentRisk,
		ExposureHistory: trend,
	}
	jsonOut := hygieneapp.Output{
		GeneratedAt:      cfg.Now,
		LookbackStart:    previousNow,
		LookbackDuration: kernel.FormatDuration(cfg.Lookback),
		DueSoonThreshold: kernel.FormatDuration(cfg.DueSoon),
		Filters: hygieneapp.Filters{
			ControlIDs: cfg.Filter.ControlIDs,
			AssetTypes: cfg.Filter.AssetTypes,
			Statuses:   cfg.Filter.Statuses,
			DueWithin:  cfg.Filter.DueWithinRaw,
		},
		SLAPosture: currentRisk,
		Trend:      trend,
	}
	return writeHygieneOutput(cfg.Format, report, jsonOut, cfg.Stdout)
}

// --- Internal Helpers ---

func buildSnapshotStats(
	cfg config,
	activeSnapshots []asset.Snapshot,
	archiveSnapshots []asset.Snapshot,
	files []appcontracts.SnapshotFile,
) appcontracts.SnapshotSummary {
	pruneCandidates := pruneretention.PlanPrune(files, retention.Criteria{
		Now:       cfg.Now,
		OlderThan: cfg.OlderThan,
		KeepMin:   cfg.KeepMin,
	})
	return appcontracts.SnapshotSummary{
		ActiveSnapshots:    len(activeSnapshots),
		HistoricalEvidence: len(archiveSnapshots),
		PurgeCandidates:    len(pruneCandidates),
		ComplianceTier:     cfg.RetentionTier,
		RetentionPolicy:    cfg.OlderThan,
		MinEvidenceCount:   cfg.KeepMin,
	}
}

func computeRiskTrend(
	ctx context.Context,
	cfg config,
	previousNow time.Time,
	controls []policy.ControlDefinition,
	activeSnapshots []asset.Snapshot,
) (appcontracts.SLAPosture, []evaluation.TrendMetric, error) {
	riskOpts := buildRiskOptions(cfg)

	svc := hygieneapp.NewService(ports.FixedClock(cfg.Now))
	currentRisk, err := svc.ComputeRisk(ctx, controls, activeSnapshots, riskOpts)
	if err != nil {
		return appcontracts.SLAPosture{}, nil, fmt.Errorf("compute current risk: %w", err)
	}

	previousSnapshots := filterSnapshotsBefore(activeSnapshots, previousNow)
	prevSvc := hygieneapp.NewService(ports.FixedClock(previousNow))
	previousRisk, err := prevSvc.ComputeRisk(ctx, controls, previousSnapshots, riskOpts)
	if err != nil {
		return appcontracts.SLAPosture{}, nil, fmt.Errorf("compute previous risk: %w", err)
	}

	trend := hygieneapp.CalculateTrend(currentRisk, previousRisk)
	return currentRisk, trend, nil
}

func buildRiskOptions(cfg config) hygieneapp.RiskOptions {
	return hygieneapp.RiskOptions{
		GlobalMaxUnsafeDuration: cfg.MaxUnsafeDuration,
		DueSoonThreshold:        cfg.DueSoon,
		StaveVersion:            staveversion.String,
		ControlIDs:              cfg.Filter.ControlIDs,
		AssetTypes:              cfg.Filter.AssetTypes,
		Statuses:                cfg.Filter.Statuses,
		DueWithin:               cfg.Filter.DueWithinPtr(),
		PredicateParser:         ctlyaml.ParsePredicate,
	}
}
