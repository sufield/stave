// Package score implements the 'stave score' command for posture scoring.
package score

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	artifact "github.com/sufield/stave/internal/adapters/artifacts"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	appscore "github.com/sufield/stave/internal/app/score"
	"github.com/sufield/stave/internal/builtin/capabilities"
	"github.com/sufield/stave/internal/core/report"
	"github.com/sufield/stave/internal/platform/fsutil"
)

type options struct {
	OutputFile string
	HistoryDir string
	Compliance string
	SLAProfile string
	WeightsStr string
	Format     string
}

// NewCmd constructs the score command.
func NewCmd() *cobra.Command {
	opts := &options{Format: "table"}

	cmd := &cobra.Command{
		Use:   "score",
		Short: "Compute security posture score (0-100)",
		Long: `Compute a normalized 0-100 security posture score from assessment
output. The score is a weighted combination of severity distribution,
SLA compliance, chain activity, and framework coverage.

Inputs:
  --output PATH       Path to a single out.v0.1.json assessment file
  --history DIR       Directory of out.v0.1.json files for score trend
  --compliance LIST   Comma-separated compliance profile names for coverage
  --sla-profile NAME  SLA profile name for SLA component scoring
  --weights STRING    Override default weights (severity=0.45,sla=0.25,
                      chain=0.20,coverage=0.10)
  --format FORMAT     Output format: table (default) | json | openmetrics

Outputs:
  stdout              Score report in the selected format

Exit Codes:
  0   Score computed
  2   Invalid input
  4   Internal error`,
		Example: `  # Current score from assessment output
  stave score --output assessment.json

  # Score with compliance coverage
  stave score --output assessment.json --compliance hipaa

  # Score trend over history
  stave score --history ./assessments/ --compliance hipaa

  # JSON output for automation
  stave score --output assessment.json --format json

  # OpenMetrics for Prometheus scraping
  stave score --output assessment.json --format openmetrics

  # Custom weights
  stave score --output assessment.json --weights severity=0.60,sla=0.20,chain=0.15,coverage=0.05`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runScore(cmd.Context(), cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.OutputFile, "output", "", "path to out.v0.1.json assessment file")
	cmd.Flags().StringVar(&opts.HistoryDir, "history", "", "directory of out.v0.1.json files for trend")
	cmd.Flags().StringVar(&opts.Compliance, "compliance", "", "comma-separated compliance profiles for coverage")
	cmd.Flags().StringVar(&opts.SLAProfile, "sla-profile", "", "SLA profile name for SLA scoring")
	cmd.Flags().StringVar(&opts.WeightsStr, "weights", "", "override weights (severity=N,sla=N,chain=N,coverage=N)")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "table", "output format: table | json | openmetrics")

	return cmd
}

func runScore(ctx context.Context, stdout io.Writer, opts *options) error {
	if opts.OutputFile == "" && opts.HistoryDir == "" {
		return errors.New("either --output or --history is required")
	}

	weights, err := appscore.ParseWeights(opts.WeightsStr)
	if err != nil {
		return fmt.Errorf("parse weights: %w", err)
	}

	// Load chain definitions for accurate chain weight.
	chains, chainsErr := ctlyaml.LoadChains("chains", capabilities.Builtin())
	if chainsErr != nil {
		return fmt.Errorf("loading chains: %w", chainsErr)
	}
	chainDefs := len(chains)
	maxChainWeight := appscore.ChainMaxWeight(chains)

	if opts.HistoryDir != "" {
		return runScoreTrend(ctx, stdout, opts, weights, chainDefs, maxChainWeight)
	}

	return runScoreSingle(ctx, stdout, opts, weights, chainDefs, maxChainWeight)
}

func runScoreSingle(ctx context.Context, stdout io.Writer, opts *options, weights appscore.Weights, chainDefs int, maxChainWeight float64) error {
	assessment, err := loadAssessment(ctx, opts.OutputFile)
	if err != nil {
		return err
	}

	// A zero-finding assessment is technically a valid input, but it
	// is also the symptom of "wrong file" or "evaluation aborted
	// before producing findings". Surface a warning so the operator
	// can confirm the input is what they intended; the score is
	// still computed because empty findings are a legitimate
	// "everything passed" reading.
	if len(assessment.Findings) == 0 {
		fmt.Fprintf(os.Stderr, "warning: %s contains zero findings — verify the path is the correct assessment\n",
			opts.OutputFile)
	}

	result := computeFromAssessment(assessment, weights, chainDefs, maxChainWeight, opts.Compliance)
	return renderResult(stdout, result, opts.Format)
}

func runScoreTrend(ctx context.Context, stdout io.Writer, opts *options, weights appscore.Weights, chainDefs int, maxChainWeight float64) error {
	assessments, err := loadHistoryAssessments(ctx, opts.HistoryDir)
	if err != nil {
		return err
	}
	if len(assessments) == 0 {
		return fmt.Errorf("no assessment files found in %s", opts.HistoryDir)
	}

	// Sort by timestamp.
	slices.SortFunc(assessments, func(a, b *report.Assessment) int {
		return a.Run.Now.Compare(b.Run.Now)
	})

	// Compute score for each run.
	results := make([]appscore.Result, len(assessments))
	for i, a := range assessments {
		results[i] = computeFromAssessment(a, weights, chainDefs, maxChainWeight, opts.Compliance)
	}

	// Single-assessment output uses latest result with trend data.
	latest := results[len(results)-1]
	latest.Trend = buildTrend(results)

	return renderResult(stdout, latest, opts.Format)
}

func computeFromAssessment(a *report.Assessment, weights appscore.Weights, chainDefs int, maxChainWeight float64, compliance string) appscore.Result {
	// Count SLA breaches.
	slaTotal := 0
	slaBreached := 0
	hasSLA := false
	for i := range a.Findings {
		f := &a.Findings[i]
		if f.SLADeadlineHours != nil {
			hasSLA = true
			slaTotal++
			if f.SLABreached {
				slaBreached++
			}
		}
	}

	// Compute coverage from framework readiness.
	var coveragePct float64
	hasCoverage := false
	if compliance != "" && len(a.Summary.FrameworkReadiness) > 0 {
		frameworks := strings.Split(compliance, ",")
		for i := range frameworks {
			frameworks[i] = strings.TrimSpace(frameworks[i])
		}
		var total float64
		var matched int
		for _, fr := range a.Summary.FrameworkReadiness {
			for _, want := range frameworks {
				if strings.EqualFold(fr.Framework, want) {
					total += float64(fr.ReadinessPercent)
					matched++
					break
				}
			}
		}
		if matched > 0 {
			hasCoverage = true
			coveragePct = total / float64(matched)
		}
	}

	// Estimate TotalCheckWeight from summary data. Each evaluation
	// contributes a severity weight. We know the violation weights
	// exactly; for passing checks we use a median weight (2.0/medium)
	// since per-severity passing data isn't in the output.
	var violationWeight float64
	for i := range a.Findings {
		violationWeight += appscore.SeverityWeightFor(a.Findings[i].ControlSeverity)
	}
	// passingAssets = assets with zero findings. The previous
	// `TotalAssets - len(Findings)` mixed scales: TotalAssets is a
	// per-asset count, len(Findings) is a per-control-per-asset count,
	// so an asset with five findings was counted five times against
	// the asset pool, producing systematically wrong (often zero or
	// negative-clamped-to-zero) passing-check counts.
	failingAssets := make(map[string]struct{}, len(a.Findings))
	for i := range a.Findings {
		failingAssets[string(a.Findings[i].AssetID)] = struct{}{}
	}
	passingChecks := max(a.Summary.TotalAssets-len(failingAssets), 0)
	totalCheckWeight := violationWeight + float64(passingChecks)*2.0

	return appscore.Compute(appscore.Input{
		Findings:         a.Findings,
		ChainFindings:    a.ChainFindings,
		ChainDefs:        chainDefs,
		MaxChainWeight:   maxChainWeight,
		SLABreached:      slaBreached,
		SLATotal:         slaTotal,
		CoveragePct:      coveragePct,
		TotalCheckWeight: totalCheckWeight,
		HasSLA:           hasSLA,
		HasCoverage:      hasCoverage,
		Weights:          weights,
		GeneratedAt:      a.Run.Now,
		SnapshotID:       snapshotID(a),
	})
}

func buildTrend(results []appscore.Result) []appscore.TrendPoint {
	points := make([]appscore.TrendPoint, len(results))
	for i := range results {
		points[i] = appscore.TrendPoint{
			Timestamp: results[i].GeneratedAt,
			Score:     results[i].Score,
		}
	}
	return points
}

func snapshotID(a *report.Assessment) string {
	if !a.Run.Now.IsZero() {
		return "snap-" + a.Run.Now.Format("20060102")
	}
	return ""
}

func loadAssessment(_ context.Context, path string) (*report.Assessment, error) {
	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return nil, fmt.Errorf("read assessment: %w", err)
	}
	var assessment report.Assessment
	if jsonErr := json.Unmarshal(data, &assessment); jsonErr != nil {
		return nil, fmt.Errorf("parse assessment: %w", jsonErr)
	}
	return &assessment, nil
}

func loadHistoryAssessments(ctx context.Context, dir string) ([]*report.Assessment, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read history directory: %w", err)
	}

	loader := artifact.NewLoader()
	var assessments []*report.Assessment
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		a, loadErr := loader.Evaluation(ctx, path)
		if loadErr != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping %s: %v\n", entry.Name(), loadErr)
			continue
		}
		assessments = append(assessments, a)
	}
	return assessments, nil
}
