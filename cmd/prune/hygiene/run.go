package hygiene

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	ctlyaml "github.com/sufield/stave/internal/adapters/input/controls/yaml"
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
	resourceTypes   []string
	statuses        []string
	dueWithin       string
}

var hygieneFlags hygieneFlagsType

func runHygiene(cmd *cobra.Command, _ []string) error {
	execCtx, err := prepareHygieneExecution(cmd)
	if err != nil {
		return err
	}
	markdown, jsonOut, err := buildHygieneOutputs(execCtx)
	if err != nil {
		return err
	}
	format, err := cmdutil.ResolveFormatValue(cmd, hygieneFlags.format)
	if err != nil {
		return err
	}
	if !cmdutil.QuietEnabled(cmd) {
		if err := writeHygieneOutput(format, markdown, jsonOut, cmd.OutOrStdout()); err != nil {
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

func prepareHygieneExecution(cmd *cobra.Command) (hygieneExecution, error) {
	req := hygieneapp.Request{
		ControlsDir:     fsutil.CleanUserPath(hygieneFlags.controlsDir),
		ObservationsDir: fsutil.CleanUserPath(hygieneFlags.observationsDir),
		ArchiveDir:      fsutil.CleanUserPath(hygieneFlags.archiveDir),
		MaxUnsafe:       hygieneFlags.maxUnsafe,
		DueSoon:         hygieneFlags.dueSoon,
		Lookback:        hygieneFlags.lookback,
		DueWithin:       hygieneFlags.dueWithin,
		OlderThan:       hygieneFlags.olderThan,
		RetentionTier:   hygieneFlags.retentionTier,
		KeepMin:         hygieneFlags.keepMin,
		NowTime:         hygieneFlags.now,
		ControlIDs:      toControlIDs(hygieneFlags.controlIDs),
		AssetTypes:      toAssetTypes(hygieneFlags.resourceTypes),
		Statuses:        toStatuses(hygieneFlags.statuses),
	}
	parsed, err := req.Parse()
	if err != nil {
		return hygieneExecution{}, err
	}
	tier, retentionDur, err := resolveHygieneRetention(cmd, req.RetentionTier, req.OlderThan)
	if err != nil {
		return hygieneExecution{}, err
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
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

func buildHygieneOutputs(execCtx hygieneExecution) (string, hygieneapp.Output, error) {
	ctx := execCtx.ctx
	req := execCtx.req
	loaded, err := cmdutil.LoadObsAndInv(ctx, req.ObservationsDir, req.ControlsDir)
	if err != nil {
		return "", hygieneapp.Output{}, err
	}
	activeSnapshots := loaded.Snapshots
	controls := loaded.Controls

	archiveSnapshots, err := loadSnapshotsIfDirExists(ctx, loaded.ObsRepo, req.ArchiveDir)
	if err != nil {
		return "", hygieneapp.Output{}, err
	}
	files, err := listObservationSnapshotFiles(req.ObservationsDir)
	if err != nil {
		return "", hygieneapp.Output{}, err
	}
	snapshotStats := buildHygieneSnapshotStats(execCtx, activeSnapshots, archiveSnapshots, files)
	currentRisk, trend := computeHygieneRiskTrend(execCtx, controls, activeSnapshots)

	reportReq := hygieneapp.ReportRequest{
		Context: hygieneapp.ReportContext{
			Now:         execCtx.now,
			PreviousNow: execCtx.previousNow,
			Lookback:    execCtx.lookbackDur,
			DueSoon:     execCtx.dueSoonDur,
		},
		Snapshots: snapshotStats,
		Risks:     currentRisk,
		Trends:    trend,
	}
	markdown := reportReq.RenderMarkdown()
	jsonOut := hygieneapp.Output{
		GeneratedAt:      execCtx.now,
		LookbackStart:    execCtx.previousNow,
		LookbackDuration: timeutil.FormatDuration(execCtx.lookbackDur),
		DueSoonThreshold: timeutil.FormatDuration(execCtx.dueSoonDur),
		Filters: map[string]any{
			"control_ids": req.ControlIDs,
			"asset_types": req.AssetTypes,
			"statuses":    req.Statuses,
			"due_within":  execCtx.filtersDueWithin,
		},
		SnapshotStats: snapshotStats,
		RiskStats:     currentRisk,
		Trend:         trend,
	}
	return markdown, jsonOut, nil
}

func buildHygieneSnapshotStats(
	execCtx hygieneExecution,
	activeSnapshots []asset.Snapshot,
	archiveSnapshots []asset.Snapshot,
	files []snapshotFile,
) hygieneapp.SnapshotStats {
	keepMin := execCtx.req.KeepMin
	pruneCandidates := planPrune(files, PruningCriteria{Now: execCtx.now, OlderThan: execCtx.retentionDur, KeepMin: keepMin})
	return hygieneapp.SnapshotStats{
		Active:            len(activeSnapshots),
		Archived:          len(archiveSnapshots),
		Total:             len(activeSnapshots) + len(archiveSnapshots),
		PruneCandidates:   len(pruneCandidates),
		RetentionTier:     execCtx.tier,
		RetentionDuration: execCtx.retentionDur,
		KeepMin:           keepMin,
	}
}

func computeHygieneRiskTrend(
	execCtx hygieneExecution,
	controls []policy.ControlDefinition,
	activeSnapshots []asset.Snapshot,
) (hygieneapp.RiskStats, []hygieneapp.TrendMetric) {
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
	tier := cmdutil.NormalizeRetentionTier(rawTier)
	if tier == "" {
		return "", 0, fmt.Errorf("--retention-tier cannot be empty")
	}
	if !cmdutil.HasConfiguredRetentionTier(tier) {
		if cfg, ok := cmdutil.FindProjectConfig(); ok && len(cfg.RetentionTiers) > 0 {
			return "", 0, fmt.Errorf("unknown --retention-tier %q (configured tiers: %s)", tier, strings.Join(cmdutil.SortedRetentionTierNames(cfg.RetentionTiers), ", "))
		}
	}
	olderThan := rawOlderThan
	if !cmd.Flags().Changed("older-than") {
		olderThan = cmdutil.ResolveSnapshotRetentionForTier(tier)
	}
	retentionDur, err := timeutil.ParseDuration(olderThan)
	if err != nil {
		return "", 0, fmt.Errorf("invalid --older-than %q (use format: 14d, 720h, or 1d12h)", olderThan)
	}
	return tier, retentionDur, nil
}
