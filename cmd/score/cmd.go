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
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	artifact "github.com/sufield/stave/internal/adapters/artifacts"
	appscore "github.com/sufield/stave/internal/app/score"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/report"
	"github.com/sufield/stave/internal/platform/fsutil"
)

type options struct {
	OutputFile string
	HistoryDir string
	Compliance string
	SLAProfile string
	Weights    string
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

The score formula:
  PostureScore = 100 × (severity×0.45 + sla×0.25 + chain×0.20 + coverage×0.10)

Flags --sla-profile and --compliance are optional. When not provided,
those components default to 1.0 (not penalized for missing config).

Exit Codes:
  0   Score computed
  2   Invalid input
  4   Internal error`,
		Example: `  stave score --output assessment.json
  stave score --output assessment.json --format json
  stave score --output assessment.json --format openmetrics
  stave score --history ./assessments/ --compliance hipaa
  stave score --output assessment.json --weights severity=0.5,sla=0.3,chain=0.1,coverage=0.1`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runScore(cmd.Context(), cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.OutputFile, "output", "", "path to out.v0.1.json")
	cmd.Flags().StringVar(&opts.HistoryDir, "history", "", "directory of out.v0.1.json files for score trend")
	cmd.Flags().StringVar(&opts.Compliance, "compliance", "", "comma-separated compliance profiles for CoverageScore")
	cmd.Flags().StringVar(&opts.SLAProfile, "sla-profile", "", "SLA profile name for SLAScore")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "table", "output format: table | json | openmetrics")
	cmd.Flags().StringVar(&opts.Weights, "weights", "", "override weights (e.g. severity=0.45,sla=0.25,chain=0.20,coverage=0.10)")

	return cmd
}

// runScore dispatches to single-file or history mode.
func runScore(ctx context.Context, stdout io.Writer, opts *options) error {
	if opts.OutputFile == "" && opts.HistoryDir == "" {
		return errors.New("exactly one of --output or --history is required: --output scores a single assessment file, --history scores a directory of assessment files for trend analysis")
	}

	weights, err := parseWeights(opts.Weights)
	if err != nil {
		return fmt.Errorf("parse weights: %w", err)
	}

	if opts.HistoryDir != "" {
		return runScoreHistory(ctx, stdout, opts, weights)
	}
	return runScoreSingle(stdout, opts, weights)
}

// runScoreSingle computes score from a single assessment file.
func runScoreSingle(stdout io.Writer, opts *options, weights appscore.Weights) error {
	data, err := fsutil.ReadFileLimited(opts.OutputFile)
	if err != nil {
		return fmt.Errorf("read assessment: %w", err)
	}
	var assessment report.Assessment
	if jsonErr := json.Unmarshal(data, &assessment); jsonErr != nil {
		return fmt.Errorf("parse assessment: %w", jsonErr)
	}

	result := computeFromAssessment(&assessment, weights)

	switch opts.Format {
	case "json":
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	case "openmetrics":
		writeOpenMetrics(stdout, result, time.Now().UnixMilli())
		return nil
	default:
		writeTable(stdout, result)
		return nil
	}
}

// scoredRun pairs a score result with its capture time.
type scoredRun struct {
	at     time.Time
	result appscore.Result
}

// runScoreHistory computes score trend across multiple assessment files.
func runScoreHistory(ctx context.Context, stdout io.Writer, opts *options, weights appscore.Weights) error {
	entries, err := os.ReadDir(opts.HistoryDir)
	if err != nil {
		return fmt.Errorf("read history directory: %w", err)
	}

	loader := artifact.NewLoader()
	var runs []scoredRun

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
		r := computeFromAssessment(a, weights)
		runs = append(runs, scoredRun{at: a.Run.Now, result: r})
	}

	if len(runs) == 0 {
		return fmt.Errorf("no assessments found in %s", opts.HistoryDir)
	}

	slices.SortFunc(runs, func(a, b scoredRun) int {
		return a.at.Compare(b.at)
	})

	latest := runs[len(runs)-1].result

	switch opts.Format {
	case "json":
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(latest)
	case "openmetrics":
		tsMs := runs[len(runs)-1].at.UnixMilli()
		writeOpenMetrics(stdout, latest, tsMs)
		return nil
	default:
		writeTableWithHistory(stdout, latest, runs)
		return nil
	}
}

// computeFromAssessment extracts score input from an assessment and computes.
func computeFromAssessment(assessment *report.Assessment, weights appscore.Weights) appscore.Result {
	slaTotal := 0
	slaBreached := 0
	hasSLA := false
	for i := range assessment.Findings {
		f := &assessment.Findings[i]
		if f.SLADeadlineHours != nil {
			hasSLA = true
			slaTotal++
			if f.SLABreached {
				slaBreached++
			}
		}
	}

	// Extract evaluation.Finding from remediation.Finding (base type).
	evalFindings := make([]evaluation.Finding, len(assessment.Findings))
	for i := range assessment.Findings {
		evalFindings[i] = assessment.Findings[i].Finding
	}

	return appscore.Compute(appscore.Input{
		Findings:      evalFindings,
		ChainFindings: assessment.ChainFindings,
		ChainDefs:     appscore.ApproximateTotalChains,
		SLABreached:   slaBreached,
		SLATotal:      slaTotal,
		HasSLA:        hasSLA,
		Weights:       weights,
	})
}

// parseWeights parses the --weights flag into a Weights struct.
// Format: "severity=0.45,sla=0.25,chain=0.20,coverage=0.10"
func parseWeights(s string) (appscore.Weights, error) {
	w := appscore.DefaultWeights()
	if s == "" {
		return w, nil
	}
	for _, part := range strings.Split(s, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			return w, fmt.Errorf("invalid weight entry %q (expected key=value)", part)
		}
		val, err := strconv.ParseFloat(strings.TrimSpace(kv[1]), 64)
		if err != nil {
			return w, fmt.Errorf("invalid weight value for %q: %w", kv[0], err)
		}
		switch strings.TrimSpace(kv[0]) {
		case "severity":
			w.Severity = val
		case "sla":
			w.SLA = val
		case "chain":
			w.Chain = val
		case "coverage":
			w.Coverage = val
		default:
			return w, fmt.Errorf("unknown weight key %q (valid: severity, sla, chain, coverage)", kv[0])
		}
	}
	return w, nil
}

func writeTable(w io.Writer, r appscore.Result) {
	fmt.Fprintf(w, "SECURITY POSTURE SCORE\n\n")
	fmt.Fprintf(w, "SCORE:  %.1f / 100   %s\n", r.Score, strings.ToUpper(r.RubricBand))
	fmt.Fprintln(w, strings.Repeat("─", 66))

	fmt.Fprintln(w, "\nSCORE DECOMPOSITION")
	fmt.Fprintf(w, "  Severity score:   %.2f × %.2f = %5.1f pts  (of %.0f max)\n",
		r.Severity.SubScore, r.Severity.Weight, r.Severity.Contribution, r.Severity.MaxContribution)
	fmt.Fprintf(w, "  SLA score:        %.2f × %.2f = %5.1f pts  (of %.0f max)\n",
		r.SLA.SubScore, r.SLA.Weight, r.SLA.Contribution, r.SLA.MaxContribution)
	fmt.Fprintf(w, "  Chain score:      %.2f × %.2f = %5.1f pts  (of %.0f max)\n",
		r.Chain.SubScore, r.Chain.Weight, r.Chain.Contribution, r.Chain.MaxContribution)
	fmt.Fprintf(w, "  Coverage score:   %.2f × %.2f = %5.1f pts  (of %.0f max)\n",
		r.Coverage.SubScore, r.Coverage.Weight, r.Coverage.Contribution, r.Coverage.MaxContribution)

	fmt.Fprintf(w, "\nRUBRIC:  %.1f = %s\n  %s\n",
		r.Score, strings.ToUpper(r.RubricBand), r.RubricDesc)
}

// writeTableWithHistory writes the score table plus a trend sparkline section.
func writeTableWithHistory(w io.Writer, latest appscore.Result, runs []scoredRun) {
	writeTable(w, latest)

	if len(runs) < 2 {
		return
	}

	const barWidth = 22
	fmt.Fprintf(w, "\nTREND (last %d runs):\n", len(runs))
	for i := range runs {
		r := &runs[i]
		dateStr := r.at.UTC().Format("2006-01-02")
		bar := scoreBar(r.result.Score, barWidth)
		marker := ""
		if i == len(runs)-1 {
			marker = "  ← latest"
		}
		fmt.Fprintf(w, "  %s  %5.1f  %s%s\n", dateStr, r.result.Score, bar, marker)
	}

	first := runs[0].result.Score
	last := runs[len(runs)-1].result.Score
	netChange := last - first
	direction := "STABLE"
	switch {
	case netChange < -0.5:
		direction = "DECLINING"
	case netChange > 0.5:
		direction = "IMPROVING"
	}
	fmt.Fprintf(w, "\nNet change (%d runs): %+.1f pts  Direction: %s\n",
		len(runs), netChange, direction)
}

// scoreBar returns a mini bar chart of filled/empty blocks for a 0-100 score.
func scoreBar(score float64, width int) string {
	filled := int(score / 100 * float64(width))
	if filled < 0 {
		filled = 0
	}
	if filled > width {
		filled = width
	}
	empty := width - filled
	return strings.Repeat("█", filled) + strings.Repeat("░", empty)
}

// writeOpenMetrics writes the full OpenMetrics posture score output.
func writeOpenMetrics(w io.Writer, r appscore.Result, tsMs int64) {
	fmt.Fprintln(w, "# HELP stave_posture_score Security posture score (0-100)")
	fmt.Fprintln(w, "# TYPE stave_posture_score gauge")
	fmt.Fprintf(w, "stave_posture_score %.1f %d\n", r.Score, tsMs)
	fmt.Fprintln(w, "# HELP stave_posture_score_severity_component Severity sub-score (0-1)")
	fmt.Fprintln(w, "# TYPE stave_posture_score_severity_component gauge")
	fmt.Fprintf(w, "stave_posture_score_severity_component %.2f %d\n", r.Severity.SubScore, tsMs)
	fmt.Fprintln(w, "# HELP stave_posture_score_sla_component SLA compliance sub-score (0-1)")
	fmt.Fprintln(w, "# TYPE stave_posture_score_sla_component gauge")
	fmt.Fprintf(w, "stave_posture_score_sla_component %.2f %d\n", r.SLA.SubScore, tsMs)
	fmt.Fprintln(w, "# HELP stave_posture_score_chain_component Chain activity sub-score (0-1)")
	fmt.Fprintln(w, "# TYPE stave_posture_score_chain_component gauge")
	fmt.Fprintf(w, "stave_posture_score_chain_component %.2f %d\n", r.Chain.SubScore, tsMs)
	fmt.Fprintln(w, "# HELP stave_posture_score_coverage_component Framework coverage sub-score (0-1)")
	fmt.Fprintln(w, "# TYPE stave_posture_score_coverage_component gauge")
	fmt.Fprintf(w, "stave_posture_score_coverage_component %.2f %d\n", r.Coverage.SubScore, tsMs)
	fmt.Fprintln(w, "# HELP stave_posture_score_rubric_band Rubric band (0=critical,1=at_risk,2=needs_attention,3=adequate,4=strong)")
	fmt.Fprintln(w, "# TYPE stave_posture_score_rubric_band gauge")
	fmt.Fprintf(w, "stave_posture_score_rubric_band %d %d\n", rubricBandInt(r.RubricBand), tsMs)
	fmt.Fprintln(w, "# EOF")
}

// rubricBandInt maps a rubric band name to a numeric value for OpenMetrics.
func rubricBandInt(band string) int {
	switch band {
	case "strong":
		return 4
	case "adequate":
		return 3
	case "needs_attention":
		return 2
	case "at_risk":
		return 1
	default: // "critical"
		return 0
	}
}
