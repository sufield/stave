// Package trendcmd is the engine behind `stave trend` (compliance posture
// trending across a sequence of assessment files) and its predict / forecast
// / oscillation subcommands. It is the engine behind pkg/stave.TrendReport /
// PredictReadiness / ForecastPosture / ClassifyOscillation; the commands keep
// only flag wiring, the pager, the --out file write, and the stderr warnings.
package trendcmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	artifact "github.com/sufield/stave/internal/adapters/artifacts"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	appscore "github.com/sufield/stave/internal/app/score"
	"github.com/sufield/stave/internal/app/teams"
	"github.com/sufield/stave/internal/core/capabilities"
	"github.com/sufield/stave/internal/core/report"
)

// TrendConfig parameterizes [TrendReport]. It mirrors the `stave trend` flags
// (minus the command-side pager / --out).
type TrendConfig struct {
	HistoryDir     string
	Files          string
	Compliance     string
	Format         string
	Window         int
	MinRuns        int
	TeamManifest   string
	Team           string
	RegressionOnly bool
	Rollup         string
}

// TrendReport loads the assessment history, computes the full posture-trend
// report (per-run metrics, MTTR, velocity, projection, framework + SLA
// trends, posture score, optional per-team trends + rollup) and renders it
// (table | json | openmetrics | executive-summary). It returns the rendered
// bytes plus any per-file load warnings (for stderr). All failures stay plain
// (exit 4). It is the library entry point behind `stave trend`.
func TrendReport(ctx context.Context, cfg TrendConfig) (output []byte, warnings []string, err error) {
	if cfg.HistoryDir == "" && cfg.Files == "" {
		return nil, nil, errors.New("either --history or --files is required")
	}

	assessments, warnings, err := loadAssessments(ctx, cfg.HistoryDir, cfg.Files)
	if err != nil {
		return nil, warnings, err
	}

	if len(assessments) == 0 || len(assessments) < cfg.MinRuns {
		reqRuns := cfg.MinRuns
		if reqRuns <= 0 {
			reqRuns = 1
		}
		return nil, warnings, fmt.Errorf("trend requires at least %d assessment files (found %d)", reqRuns, len(assessments))
	}

	slices.SortFunc(assessments, func(a, b *report.Assessment) int {
		switch {
		case a.Before(b):
			return -1
		case b.Before(a):
			return 1
		default:
			return 0
		}
	})

	if cfg.Window > 0 && len(assessments) > cfg.Window {
		assessments = assessments[len(assessments)-cfg.Window:]
	}

	runs := make([]runMetrics, len(assessments))
	for i, a := range assessments {
		var prev *runMetrics
		if i > 0 {
			prev = &runs[i-1]
		}
		runs[i] = computeRunMetrics(a, prev)
		runs[i].FilePath = ""
	}

	mttr := computeMTTR(assessments)
	velocity := computeVelocity(runs, 5)
	projection := computeProjection(runs, velocity)
	frameworkTrends := computeFrameworkTrends(assessments, cfg.Compliance)
	slaTrend := computeSLATrend(assessments)

	chains, chainsErr := ctlyaml.LoadChains("chains", capabilities.Builtin())
	if chainsErr != nil {
		return nil, warnings, fmt.Errorf("loading chains: %w", chainsErr)
	}
	chainDefs := len(chains)
	maxChainWeight := appscore.ChainMaxWeight(chains)

	latestAssessment := assessments[len(assessments)-1]
	scoreResult := computePostureScore(latestAssessment, slaTrend, chainDefs, maxChainWeight)

	rep := trendReport{
		GeneratedAt: time.Now().UTC(),
		Period: period{
			Start:    assessments[0].Run.EvalTime,
			End:      assessments[len(assessments)-1].Run.EvalTime,
			RunCount: len(assessments),
		},
		Summary: trendSummary{
			FirstViolationRate:  runs[0].ViolationRate,
			LatestViolationRate: runs[len(runs)-1].ViolationRate,
		},
		Runs:            runs,
		MTTR:            mttr,
		FrameworkTrends: frameworkTrends,
		Velocity:        velocity,
		Projection:      projection,
		SLATrend:        slaTrend,
		PostureScore:    &scoreResult.Score,
		PostureRubric:   string(scoreResult.RubricBand),
	}

	if rep.Summary.FirstViolationRate > 0 {
		change := (rep.Summary.LatestViolationRate - rep.Summary.FirstViolationRate) /
			rep.Summary.FirstViolationRate * 100
		rep.Summary.NetChangePercent = change
	}
	rep.Summary.Direction = velocity.Direction

	if cfg.TeamManifest != "" {
		manifest, manifestErr := teams.LoadManifest(cfg.TeamManifest)
		if manifestErr != nil {
			return nil, warnings, fmt.Errorf("load team manifest: %w", manifestErr)
		}
		teamTrends, teamSummary := computeTeamTrends(assessments, manifest, cfg.Team, cfg.RegressionOnly)
		rep.TeamTrends = teamTrends
		rep.TeamSummary = teamSummary

		if cfg.Rollup != "" {
			group := manifest.HierarchyByID(cfg.Rollup)
			if group == nil {
				return nil, warnings, fmt.Errorf("hierarchy group %q not found in manifest", cfg.Rollup)
			}
			rep.Rollup = computeRollup(teamTrends, group)
		}
	}

	var buf bytes.Buffer
	if rErr := renderTrend(cfg.Format, &buf, &rep); rErr != nil {
		return nil, warnings, rErr
	}
	return buf.Bytes(), warnings, nil
}

func computePostureScore(a *report.Assessment, slaTrend []slaTrendMetric, chainDefs int, maxChainWeight float64) appscore.Result {
	slaTotal, slaBreached := a.SLASummary()
	hasSLA := slaTotal > 0
	if !hasSLA && len(slaTrend) > 0 {
		latest := slaTrend[len(slaTrend)-1]
		if latest.TotalWithSLA > 0 {
			hasSLA = true
			slaTotal = latest.TotalWithSLA
			slaBreached = latest.BreachedCount
		}
	}

	return appscore.Compute(appscore.Input{
		Findings:       a.Findings,
		ChainFindings:  a.ChainFindings,
		ChainDefs:      chainDefs,
		MaxChainWeight: maxChainWeight,
		SLABreached:    slaBreached,
		SLATotal:       slaTotal,
		HasSLA:         hasSLA,
		Weights:        appscore.DefaultWeights(),
		GeneratedAt:    a.Run.EvalTime,
	})
}

// loadAssessments loads every assessment named by the config (an explicit
// comma-separated Files list, or every *.json in HistoryDir). Per-file load
// failures inside the directory walk are non-fatal: they are collected as
// warnings (returned for the caller to print to stderr) and the walk
// continues.
func loadAssessments(ctx context.Context, historyDir, files string) ([]*report.Assessment, []string, error) {
	loader := artifact.NewLoader()

	if files != "" {
		var assessments []*report.Assessment
		p := files
		for p != "" {
			var seg string
			seg, p, _ = strings.Cut(p, ",")
			seg = strings.TrimSpace(seg)
			a, err := loader.Evaluation(ctx, seg)
			if err != nil {
				return nil, nil, fmt.Errorf("load %s: %w", seg, err)
			}
			assessments = append(assessments, a)
		}
		return assessments, nil, nil
	}

	entries, err := os.ReadDir(historyDir)
	if err != nil {
		return nil, nil, fmt.Errorf("read history directory: %w", err)
	}

	var assessments []*report.Assessment
	var warnings []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(historyDir, entry.Name())
		a, loadErr := loader.Evaluation(ctx, path)
		if loadErr != nil {
			warnings = append(warnings, fmt.Sprintf("warning: skipping %s: %v", entry.Name(), loadErr))
			continue
		}
		assessments = append(assessments, a)
	}

	return assessments, warnings, nil
}
