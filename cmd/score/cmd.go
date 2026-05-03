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
	"github.com/sufield/stave/internal/core/capabilities"
	"github.com/sufield/stave/internal/core/report"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/stave"
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
	if !assessment.HasFindings() {
		fmt.Fprintf(os.Stderr, "warning: %s contains zero findings — verify the path is the correct assessment\n",
			opts.OutputFile)
	}

	result := computeFromAssessment(ctx, assessment, weights, chainDefs, maxChainWeight, opts.Compliance)
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

	// Sort by timestamp via Assessment.Before.
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

	// Compute score for each run.
	results := make([]appscore.Result, len(assessments))
	for i, a := range assessments {
		results[i] = computeFromAssessment(ctx, a, weights, chainDefs, maxChainWeight, opts.Compliance)
	}

	// Single-assessment output uses latest result with trend data.
	latest := results[len(results)-1]
	latest.Trend = buildTrend(results)

	return renderResult(stdout, latest, opts.Format)
}

// computeFromAssessment delegates to stave.Score so library and
// CLI verdicts share the same code path.
//
// The internal *report.Assessment loaded from disk is converted to
// the public *stave.Assessment shape (lossless for scoring inputs)
// and passed through the library's pure-arithmetic Score entry
// point. The library replicates the same SLA tally, coverage
// average, and TotalCheckWeight estimation that used to live here.
func computeFromAssessment(ctx context.Context, a *report.Assessment, weights appscore.Weights, chainDefs int, maxChainWeight float64, compliance string) appscore.Result {
	pubAsmt := stave.FromReportAssessment(a)
	w := weights
	cfg := stave.ScoreConfig{
		Assessment:     pubAsmt,
		Weights:        &w,
		ChainMaxWeight: maxChainWeight,
		ChainDefs:      chainDefs,
		Compliance:     parseComplianceList(compliance),
		SnapshotID:     a.SnapshotID(),
	}
	res, err := stave.Score(ctx, cfg)
	if err != nil {
		// Score's only documented error is a nil Assessment, which
		// we just constructed — surface it as a programming-error
		// fallback rather than masking with a default-zero result.
		return appscore.Result{}
	}
	return *res
}

// parseComplianceList splits the comma-separated CLI flag value into
// trimmed, non-empty framework names. Empty input returns nil.
func parseComplianceList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
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
