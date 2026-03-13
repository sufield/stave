package hygiene

import (
	"context"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	pruneshared "github.com/sufield/stave/cmd/prune/shared"
	ctlyaml "github.com/sufield/stave/internal/adapters/input/controls/yaml"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	hygieneapp "github.com/sufield/stave/internal/app/hygiene"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/pkg/timeutil"
	"github.com/sufield/stave/internal/platform/fsutil"
	staveversion "github.com/sufield/stave/internal/version"
)

type hygieneFlagsType struct {
	controlsDir     string
	observationsDir string
	archiveDir      string
	maxUnsafe       string
	dueSoon         string
	lookback        string
	olderThan       string
	retentionTier   string
	keepMin         int
	now             string
	format          string
	controlIDs      []string
	assetTypes      []string
	statuses        []string
	dueWithin       string
}

func runHygiene(cmd *cobra.Command, flags *hygieneFlagsType) error {
	execCtx, err := prepareHygieneExecution(cmd, flags)
	if err != nil {
		return err
	}
	reportReq, jsonOut, err := buildHygieneOutputs(execCtx)
	if err != nil {
		return err
	}
	format, err := compose.ResolveFormatValue(cmd, flags.format)
	if err != nil {
		return err
	}
	if !cmdutil.QuietEnabled(cmd) {
		if err := writeHygieneOutput(format, reportReq, jsonOut, cmd.OutOrStdout()); err != nil {
			return err
		}
	}

	return nil
}

type hygieneExecution struct {
	ctx              context.Context
	req              hygieneapp.Request
	now              time.Time
	previousNow      time.Time
	lookbackDur      time.Duration
	dueSoonDur       time.Duration
	retentionDur     time.Duration
	tier             string
	riskOpts         hygieneapp.RiskOptions
	filtersDueWithin string
}

func prepareHygieneExecution(cmd *cobra.Command, flags *hygieneFlagsType) (hygieneExecution, error) {
	req := hygieneapp.Request{
		ControlsDir:     fsutil.CleanUserPath(flags.controlsDir),
		ObservationsDir: fsutil.CleanUserPath(flags.observationsDir),
		ArchiveDir:      fsutil.CleanUserPath(flags.archiveDir),
		MaxUnsafe:       flags.maxUnsafe,
		DueSoon:         flags.dueSoon,
		Lookback:        flags.lookback,
		DueWithin:       flags.dueWithin,
		OlderThan:       flags.olderThan,
		RetentionTier:   flags.retentionTier,
		KeepMin:         flags.keepMin,
		NowTime:         flags.now,
		ControlIDs:      cmdutil.ToControlIDs(flags.controlIDs),
		AssetTypes:      cmdutil.ToAssetTypes(flags.assetTypes),
		Statuses:        toStatuses(flags.statuses),
	}
	parsed, err := req.Parse()
	if err != nil {
		return hygieneExecution{}, err
	}
	tier, retentionDur, err := resolveHygieneRetention(cmd, req.RetentionTier, req.OlderThan)
	if err != nil {
		return hygieneExecution{}, err
	}
	ctx := compose.CommandContext(cmd)
	return hygieneExecution{
		ctx:              ctx,
		req:              req,
		now:              parsed.Now,
		previousNow:      parsed.Now.Add(-parsed.Lookback),
		lookbackDur:      parsed.Lookback,
		dueSoonDur:       parsed.DueSoon,
		retentionDur:     retentionDur,
		tier:             tier,
		filtersDueWithin: req.DueWithin,
		riskOpts: hygieneapp.RiskOptions{
			GlobalMaxUnsafe:  parsed.MaxUnsafe,
			Now:              parsed.Now,
			DueSoonThreshold: parsed.DueSoon,
			ToolVersion:      staveversion.Version,
			ControlIDs:       req.ControlIDs,
			AssetTypes:       req.AssetTypes,
			Statuses:         req.Statuses,
			DueWithin:        parsed.DueWithin,
			PredicateParser:  ctlyaml.YAMLPredicateParser,
		},
	}, nil
}

func buildHygieneOutputs(execCtx hygieneExecution) (appcontracts.ReportRequest, hygieneapp.Output, error) {
	ctx := execCtx.ctx
	req := execCtx.req
	loaded, err := compose.ActiveProvider().LoadAssets(ctx, req.ObservationsDir, req.ControlsDir)
	if err != nil {
		return appcontracts.ReportRequest{}, hygieneapp.Output{}, err
	}
	activeSnapshots := loaded.Snapshots
	controls := loaded.Controls

	obsRepo, err := compose.ActiveProvider().NewObservationRepo()
	if err != nil {
		return appcontracts.ReportRequest{}, hygieneapp.Output{}, err
	}
	archiveSnapshots, err := loadSnapshotsIfDirExists(ctx, obsRepo, req.ArchiveDir)
	if err != nil {
		return appcontracts.ReportRequest{}, hygieneapp.Output{}, err
	}
	files, err := listObservationSnapshotFiles(ctx, req.ObservationsDir)
	if err != nil {
		return appcontracts.ReportRequest{}, hygieneapp.Output{}, err
	}
	snapshotStats := buildHygieneSnapshotStats(execCtx, activeSnapshots, archiveSnapshots, files)
	currentRisk, trend := computeHygieneRiskTrend(execCtx, controls, activeSnapshots)

	reportReq := appcontracts.ReportRequest{
		Context: appcontracts.ReportContext{
			Now:         execCtx.now,
			PreviousNow: execCtx.previousNow,
			Lookback:    execCtx.lookbackDur,
			DueSoon:     execCtx.dueSoonDur,
		},
		Snapshots: snapshotStats,
		Risks:     currentRisk,
		Trends:    trend,
	}
	jsonOut := hygieneapp.Output{
		GeneratedAt:      execCtx.now,
		LookbackStart:    execCtx.previousNow,
		LookbackDuration: timeutil.FormatDuration(execCtx.lookbackDur),
		DueSoonThreshold: timeutil.FormatDuration(execCtx.dueSoonDur),
		Filters: hygieneapp.HygieneFilters{
			ControlIDs: req.ControlIDs,
			AssetTypes: req.AssetTypes,
			Statuses:   req.Statuses,
			DueWithin:  execCtx.filtersDueWithin,
		},
		SnapshotStats: snapshotStats,
		RiskStats:     currentRisk,
		Trend:         trend,
	}
	return reportReq, jsonOut, nil
}

func buildHygieneSnapshotStats(
	execCtx hygieneExecution,
	activeSnapshots []asset.Snapshot,
	archiveSnapshots []asset.Snapshot,
	files []snapshotFile,
) appcontracts.SnapshotStats {
	keepMin := execCtx.req.KeepMin
	pruneCandidates := planPrune(files, PruningCriteria{Now: execCtx.now, OlderThan: execCtx.retentionDur, KeepMin: keepMin})
	return appcontracts.NewSnapshotStats(
		len(activeSnapshots),
		len(archiveSnapshots),
		len(pruneCandidates),
		keepMin,
		execCtx.tier,
		execCtx.retentionDur,
	)
}

func computeHygieneRiskTrend(
	execCtx hygieneExecution,
	controls []policy.ControlDefinition,
	activeSnapshots []asset.Snapshot,
) (appcontracts.RiskStats, []appcontracts.TrendMetric) {
	svc := hygieneapp.NewService()
	previousNow := execCtx.previousNow
	riskOpts := execCtx.riskOpts
	currentRisk := svc.ComputeRisk(controls, activeSnapshots, riskOpts)
	previousSnapshots := filterSnapshotsBefore(activeSnapshots, previousNow)
	previousOpts := riskOpts
	previousOpts.Now = previousNow
	previousRisk := svc.ComputeRisk(controls, previousSnapshots, previousOpts)
	trend := hygieneapp.CalculateTrend(currentRisk, previousRisk)
	return currentRisk, trend
}

func resolveHygieneRetention(cmd *cobra.Command, rawTier, rawOlderThan string) (string, time.Duration, error) {
	tier, err := pruneshared.ValidateRetentionTier(rawTier)
	if err != nil {
		return "", 0, err
	}
	retentionDur, err := pruneshared.ResolveOlderThan(cmd, rawOlderThan, tier)
	if err != nil {
		return "", 0, err
	}
	return tier, retentionDur, nil
}
