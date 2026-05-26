// Package score implements the 'stave score' command for posture scoring.
package score

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

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
		return fmt.Errorf("either --output or --history is required: %w", stave.ErrInvalidInput)
	}

	weights, err := stave.ParseWeights(opts.WeightsStr)
	if err != nil {
		// Weights parse failures are bad user input — wrap so the
		// root exit-code shim maps to exit 2, not exit 4.
		return fmt.Errorf("parse weights: %w: %w", err, stave.ErrInvalidInput)
	}

	budget, err := stave.BuiltinChainBudget()
	if err != nil {
		return err
	}

	if opts.HistoryDir != "" {
		return runScoreTrend(ctx, stdout, opts, weights, budget)
	}

	return runScoreSingle(ctx, stdout, opts, weights, budget)
}

func runScoreSingle(ctx context.Context, stdout io.Writer, opts *options, weights stave.Weights, budget stave.ChainBudget) error {
	assessment, err := stave.LoadAssessment(ctx, opts.OutputFile)
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

	result, err := computeFromAssessment(ctx, assessment, weights, budget, opts.Compliance)
	if err != nil {
		return err
	}
	return renderResult(stdout, result, opts.Format)
}

func runScoreTrend(ctx context.Context, stdout io.Writer, opts *options, weights stave.Weights, budget stave.ChainBudget) error {
	assessments, err := stave.LoadAssessments(ctx, opts.HistoryDir)
	if err != nil {
		return err
	}
	if len(assessments) == 0 {
		return fmt.Errorf("no assessment files found in %s", opts.HistoryDir)
	}

	// Stable sort keeps the directory-load order intact when two
	// assessments share an identical timestamp — without it, the
	// scorer would emit non-deterministic trend output run-to-run
	// for sequential assessments produced inside the same
	// wall-clock second.
	stave.SortAssessmentsByTime(assessments)

	// Compute score for each run.
	results := make([]stave.ScoreResult, len(assessments))
	for i, a := range assessments {
		r, err := computeFromAssessment(ctx, a, weights, budget, opts.Compliance)
		if err != nil {
			return fmt.Errorf("score history entry %d: %w", i, err)
		}
		results[i] = r
	}

	// Single-assessment output uses latest result with trend data.
	latest := results[len(results)-1]
	latest.Trend = buildTrend(results)

	return renderResult(stdout, latest, opts.Format)
}

// computeFromAssessment delegates to stave.Score so library and
// CLI verdicts share the same code path.
//
// Returns the underlying error so callers fail loud on misuse —
// the previous shape silently returned a zero-value result that
// rendered as "score 0", indistinguishable from a real
// "everything broken" verdict.
func computeFromAssessment(ctx context.Context, a *stave.Assessment, weights stave.Weights, budget stave.ChainBudget, compliance string) (stave.ScoreResult, error) {
	w := weights
	cfg := stave.ScoreConfig{
		Assessment:     a,
		Weights:        &w,
		ChainMaxWeight: budget.MaxWeight,
		ChainDefs:      budget.ChainDefs,
		Compliance:     parseComplianceList(compliance),
		SnapshotID:     a.SnapshotID(),
	}
	res, err := stave.Score(ctx, cfg)
	if err != nil {
		return stave.ScoreResult{}, fmt.Errorf("score assessment: %w", err)
	}
	return *res, nil
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

func buildTrend(results []stave.ScoreResult) []stave.TrendPoint {
	points := make([]stave.TrendPoint, len(results))
	for i := range results {
		points[i] = stave.TrendPoint{
			Timestamp: results[i].GeneratedAt,
			Score:     results[i].Score,
		}
	}
	return points
}
