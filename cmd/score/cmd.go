// Package score implements the 'stave score' command for posture scoring.
package score

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	appscore "github.com/sufield/stave/internal/app/score"
	"github.com/sufield/stave/internal/core/report"
	"github.com/sufield/stave/internal/platform/fsutil"
)

type options struct {
	OutputFile string
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

Exit Codes:
  0   Score computed
  2   Invalid input
  4   Internal error`,
		Example: `  stave score --output assessment.json
  stave score --output assessment.json --format json
  stave score --output assessment.json --format openmetrics`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runScore(cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.OutputFile, "output", "", "path to out.v0.1.json (required)")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "table", "output format: table | json | openmetrics")
	_ = cmd.MarkFlagRequired("output")

	return cmd
}

func runScore(stdout io.Writer, opts *options) error {
	data, err := fsutil.ReadFileLimited(opts.OutputFile)
	if err != nil {
		return fmt.Errorf("read assessment: %w", err)
	}
	var assessment report.Assessment
	if jsonErr := json.Unmarshal(data, &assessment); jsonErr != nil {
		return fmt.Errorf("parse assessment: %w", jsonErr)
	}

	// Count SLA breaches.
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

	result := appscore.Compute(appscore.Input{
		Findings:      assessment.Findings,
		ChainFindings: assessment.ChainFindings,
		ChainDefs:     50, // approximate — total chain definitions
		SLABreached:   slaBreached,
		SLATotal:      slaTotal,
		HasSLA:        hasSLA,
		Weights:       appscore.DefaultWeights(),
	})

	switch opts.Format {
	case "json":
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	case "openmetrics":
		writeOpenMetrics(stdout, result)
		return nil
	default:
		writeTable(stdout, result)
		return nil
	}
}

func writeTable(w io.Writer, r appscore.Result) {
	fmt.Fprintf(w, "SECURITY POSTURE SCORE\n\n")
	fmt.Fprintf(w, "SCORE:  %.1f / 100   %s\n", r.Score, strings.ToUpper(r.RubricBand))
	fmt.Fprintln(w, strings.Repeat("-", 50))

	fmt.Fprintln(w, "\nSCORE DECOMPOSITION")
	fmt.Fprintf(w, "  Severity:  %.2f x %.2f = %5.1f pts  (of %.0f max)\n",
		r.Severity.SubScore, r.Severity.Weight, r.Severity.Contribution, r.Severity.MaxContribution)
	fmt.Fprintf(w, "  SLA:       %.2f x %.2f = %5.1f pts  (of %.0f max)\n",
		r.SLA.SubScore, r.SLA.Weight, r.SLA.Contribution, r.SLA.MaxContribution)
	fmt.Fprintf(w, "  Chain:     %.2f x %.2f = %5.1f pts  (of %.0f max)\n",
		r.Chain.SubScore, r.Chain.Weight, r.Chain.Contribution, r.Chain.MaxContribution)
	fmt.Fprintf(w, "  Coverage:  %.2f x %.2f = %5.1f pts  (of %.0f max)\n",
		r.Coverage.SubScore, r.Coverage.Weight, r.Coverage.Contribution, r.Coverage.MaxContribution)

	fmt.Fprintf(w, "\nRubric: %s\n  %s\n", strings.ToUpper(r.RubricBand), r.RubricDesc)
}

func writeOpenMetrics(w io.Writer, r appscore.Result) {
	fmt.Fprintln(w, "# HELP stave_posture_score Security posture score (0-100)")
	fmt.Fprintln(w, "# TYPE stave_posture_score gauge")
	fmt.Fprintf(w, "stave_posture_score %.1f\n", r.Score)
	fmt.Fprintln(w, "# HELP stave_posture_score_severity_component Severity sub-score (0-1)")
	fmt.Fprintln(w, "# TYPE stave_posture_score_severity_component gauge")
	fmt.Fprintf(w, "stave_posture_score_severity_component %.2f\n", r.Severity.SubScore)
	fmt.Fprintln(w, "# HELP stave_posture_score_sla_component SLA compliance sub-score (0-1)")
	fmt.Fprintln(w, "# TYPE stave_posture_score_sla_component gauge")
	fmt.Fprintf(w, "stave_posture_score_sla_component %.2f\n", r.SLA.SubScore)
	fmt.Fprintln(w, "# HELP stave_posture_score_chain_component Chain activity sub-score (0-1)")
	fmt.Fprintln(w, "# TYPE stave_posture_score_chain_component gauge")
	fmt.Fprintf(w, "stave_posture_score_chain_component %.2f\n", r.Chain.SubScore)
	fmt.Fprintln(w, "# HELP stave_posture_score_coverage_component Framework coverage sub-score (0-1)")
	fmt.Fprintln(w, "# TYPE stave_posture_score_coverage_component gauge")
	fmt.Fprintf(w, "stave_posture_score_coverage_component %.2f\n", r.Coverage.SubScore)
	fmt.Fprintln(w, "# EOF")
}
