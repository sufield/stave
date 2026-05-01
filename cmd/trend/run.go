package trend

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	artifact "github.com/sufield/stave/internal/adapters/artifacts"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	appscore "github.com/sufield/stave/internal/app/score"
	"github.com/sufield/stave/internal/app/teams"
	"github.com/sufield/stave/internal/builtin/capabilities"
	"github.com/sufield/stave/internal/core/report"
)

func runTrend(ctx context.Context, w io.Writer, opts *trendOptions) error {
	if opts.HistoryDir == "" && opts.Files == "" {
		return errors.New("either --history or --files is required")
	}

	assessments, err := loadAssessments(ctx, opts)
	if err != nil {
		return err
	}

	if len(assessments) < opts.MinRuns {
		return fmt.Errorf("trend requires at least %d assessment files (found %d)", opts.MinRuns, len(assessments))
	}

	// Sort by timestamp.
	slices.SortFunc(assessments, func(a, b *report.Assessment) int {
		return a.Run.Now.Compare(b.Run.Now)
	})

	// Apply window limit.
	if opts.Window > 0 && len(assessments) > opts.Window {
		assessments = assessments[len(assessments)-opts.Window:]
	}

	// Compute per-run metrics.
	runs := make([]runMetrics, len(assessments))
	for i, a := range assessments {
		var prev *runMetrics
		if i > 0 {
			prev = &runs[i-1]
		}
		runs[i] = computeRunMetrics(a, prev)
		runs[i].FilePath = "" // not tracked in this path
	}

	// Compute MTTR.
	mttr := computeMTTR(assessments)

	// Compute velocity.
	velocity := computeVelocity(runs, 5)

	// Compute projection.
	projection := computeProjection(runs, velocity)

	// Compute framework trends.
	frameworkTrends := computeFrameworkTrends(assessments, opts.Compliance)

	// Compute SLA compliance trend.
	slaTrend := computeSLATrend(assessments)

	// Load chain definitions for accurate chain weight.
	chains, chainsErr := ctlyaml.LoadChains("chains", capabilities.Builtin())
	if chainsErr != nil {
		return fmt.Errorf("loading chains: %w", chainsErr)
	}
	chainDefs := len(chains)
	maxChainWeight := appscore.ChainMaxWeight(chains)

	// Compute posture score from latest assessment.
	latestAssessment := assessments[len(assessments)-1]
	scoreResult := computePostureScore(latestAssessment, slaTrend, chainDefs, maxChainWeight)

	// Build report.
	report := trendReport{
		GeneratedAt: time.Now().UTC(),
		Period: period{
			Start:    assessments[0].Run.Now,
			End:      assessments[len(assessments)-1].Run.Now,
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
		PostureRubric:   scoreResult.RubricBand,
	}

	// Compute summary direction.
	if report.Summary.FirstViolationRate > 0 {
		change := (report.Summary.LatestViolationRate - report.Summary.FirstViolationRate) /
			report.Summary.FirstViolationRate * 100
		report.Summary.NetChangePercent = change
	}
	report.Summary.Direction = velocity.Direction

	// Per-team trends if manifest provided.
	if opts.TeamManifest != "" {
		manifest, manifestErr := teams.LoadManifest(opts.TeamManifest)
		if manifestErr != nil {
			return fmt.Errorf("load team manifest: %w", manifestErr)
		}
		teamTrends, teamSummary := computeTeamTrends(assessments, manifest, opts.Team, opts.RegressionOnly)
		report.TeamTrends = teamTrends
		report.TeamSummary = teamSummary

		if opts.Rollup != "" {
			group := manifest.HierarchyByID(opts.Rollup)
			if group == nil {
				return fmt.Errorf("hierarchy group %q not found in manifest", opts.Rollup)
			}
			report.Rollup = computeRollup(teamTrends, group)
		}
	}

	// Write output.
	out := w
	if opts.Out != "" {
		f, fileErr := os.Create(opts.Out)
		if fileErr != nil {
			return fmt.Errorf("create output file: %w", fileErr)
		}
		defer f.Close()
		out = f
	}

	switch opts.Format {
	case "json":
		return renderTrendJSON(out, &report)
	case "openmetrics":
		return renderTrendOpenMetrics(out, &report)
	case "executive-summary":
		return renderExecutiveSummary(out, &report)
	default:
		return renderTrendTable(out, &report)
	}
}

func computePostureScore(a *report.Assessment, slaTrend []slaTrendMetric, chainDefs int, maxChainWeight float64) appscore.Result {
	slaTotal := 0
	slaBreached := 0
	hasSLA := false
	for i := range a.Findings {
		if a.Findings[i].SLADeadlineHours != nil {
			hasSLA = true
			slaTotal++
			if a.Findings[i].SLABreached {
				slaBreached++
			}
		}
	}
	// Use SLA trend data if no per-finding SLA.
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
		GeneratedAt:    a.Run.Now,
	})
}

func loadAssessments(ctx context.Context, opts *trendOptions) ([]*report.Assessment, error) {
	loader := artifact.NewLoader()

	if opts.Files != "" {
		paths := strings.Split(opts.Files, ",")
		var assessments []*report.Assessment
		for _, p := range paths {
			p = strings.TrimSpace(p)
			a, err := loader.Evaluation(ctx, p)
			if err != nil {
				return nil, fmt.Errorf("load %s: %w", p, err)
			}
			assessments = append(assessments, a)
		}
		return assessments, nil
	}

	// Walk history directory.
	entries, err := os.ReadDir(opts.HistoryDir)
	if err != nil {
		return nil, fmt.Errorf("read history directory: %w", err)
	}

	var assessments []*report.Assessment
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(opts.HistoryDir, entry.Name())
		a, loadErr := loader.Evaluation(ctx, path)
		if loadErr != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping %s: %v\n", entry.Name(), loadErr)
			continue
		}
		assessments = append(assessments, a)
	}

	return assessments, nil
}
