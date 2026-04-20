package trend

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/app/oscillation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
	"github.com/sufield/stave/internal/metadata"
)

func newOscillationCmd() *cobra.Command {
	var historyDir, files, format string
	var minOscillations int

	cmd := &cobra.Command{
		Use:   "oscillation",
		Short: "Classify violation oscillation patterns across assessment history",
		Long: `Classify control-asset pairs into oscillation patterns (chronic,
deploy-time, or random) by analyzing state transitions across a
sequence of assessment files.

Chronic patterns indicate persistent violations (>80%% failure rate).
Deploy-time patterns indicate violations that toggle with deployments.
Random patterns indicate no discernible oscillation pattern.

Inputs:
  --history            Directory of out.v0.1 assessment files
  --files              Comma-separated assessment files
  --min-oscillations   Minimum state transitions for deploy-time (default: 3)
  --format             Output format: table or json (default: table)

Exit Codes:
  0   Analysis complete
  2   Invalid input or insufficient data` + metadata.OfflineHelpSuffix,
		Example: `  stave trend oscillation --history ./assessments/
  stave trend oscillation --history ./assessments/ --min-oscillations 5
  stave trend oscillation --history ./assessments/ --format json`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if historyDir == "" && files == "" {
				return errors.New("either --history or --files is required")
			}

			tOpts := &trendOptions{HistoryDir: historyDir, Files: files, MinRuns: 2}
			assessments, err := loadAssessments(cmd.Context(), tOpts)
			if err != nil {
				return err
			}
			if len(assessments) < 2 {
				return fmt.Errorf("oscillation analysis requires at least 2 assessment files (found %d)", len(assessments))
			}

			// Sort by timestamp.
			slices.SortFunc(assessments, func(a, b *report.Assessment) int {
				return a.Run.Now.Compare(b.Run.Now)
			})

			// Dereference to value slice for oscillation.Input.
			vals := make([]report.Assessment, len(assessments))
			for i, a := range assessments {
				vals[i] = *a
			}

			// Build set of all (controlID, assetID) pairs.
			type fkey struct{ ctl, ast string }
			pairs := make(map[fkey]bool)
			for i := range vals {
				for j := range vals[i].Findings {
					f := &vals[i].Findings[j]
					pairs[fkey{string(f.ControlID), string(f.AssetID)}] = true
				}
			}

			// Classify each pair.
			var results []oscillation.Classification
			for k := range pairs {
				c := oscillation.Classify(oscillation.Input{
					Assessments:     vals,
					ControlID:       kernel.ControlID(k.ctl),
					AssetID:         k.ast,
					MinOscillations: minOscillations,
				})
				if c.Pattern != "" {
					results = append(results, c)
				}
			}

			// Sort results for deterministic output.
			slices.SortFunc(results, func(a, b oscillation.Classification) int {
				if a.Pattern != b.Pattern {
					return strings.Compare(a.Pattern, b.Pattern)
				}
				if a.ControlID != b.ControlID {
					return strings.Compare(a.ControlID, b.ControlID)
				}
				return strings.Compare(a.AssetID, b.AssetID)
			})

			return renderOscillation(cmd.OutOrStdout(), results, format)
		},
	}

	cmd.Flags().StringVar(&historyDir, "history", "", "Directory of out.v0.1 assessment files")
	cmd.Flags().StringVar(&files, "files", "", "Comma-separated assessment files in chronological order")
	cmd.Flags().IntVar(&minOscillations, "min-oscillations", 3, "Minimum state transitions for deploy-time classification")
	cmd.Flags().StringVarP(&format, "format", "f", "table", "Output format: table or json")

	return cmd
}

// renderOscillation writes the classification results in the
// requested format. Takes an io.Writer so the caller — typically
// RunE resolving cmd.OutOrStdout() — owns the cobra boundary; this
// function stays off the cobra import graph.
func renderOscillation(w io.Writer, results []oscillation.Classification, format string) error {
	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	}
	writeOscillationTable(w, results)
	return nil
}

func writeOscillationTable(w io.Writer, results []oscillation.Classification) {
	if len(results) == 0 {
		fmt.Fprintln(w, "No oscillation patterns detected.")
		return
	}

	fmt.Fprintln(w, "OSCILLATION ANALYSIS")
	fmt.Fprintln(w, strings.Repeat("-", 90))
	fmt.Fprintf(w, "%-14s %-30s %-30s %6s %5s %s\n",
		"Pattern", "Control", "Asset", "Fail%", "Cycles", "Confidence")
	fmt.Fprintf(w, "%-14s %-30s %-30s %6s %5s %s\n",
		strings.Repeat("-", 14), strings.Repeat("-", 30), strings.Repeat("-", 30),
		strings.Repeat("-", 6), strings.Repeat("-", 5), strings.Repeat("-", 10))

	for i := range results {
		r := &results[i]
		fmt.Fprintf(w, "%-14s %-30s %-30s %5.0f%% %5d %.2f\n",
			r.Pattern, truncate(r.ControlID, 30), truncate(r.AssetID, 30),
			r.FailureRate*100, r.Cycles, r.Confidence)
	}
}

func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit-3] + "..."
}
