// Package rank implements the 'stave rank' command for producing a
// prioritized remediation roadmap from assessment output.
package rank

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	apprank "github.com/sufield/stave/internal/app/rank"
	"github.com/sufield/stave/internal/core/report"
)

type options struct {
	InputPath           string
	TopN                int
	Format              string
	IncludeAcknowledged bool
}

// NewCmd constructs the top-level rank command.
func NewCmd() *cobra.Command {
	opts := &options{
		TopN:   5,
		Format: "text",
	}

	cmd := &cobra.Command{
		Use:   "rank",
		Short: "Produce a prioritized remediation roadmap from assessment output",
		Long: `Rank reads assessment JSON (from stave apply) and produces a prioritized
remediation roadmap. Findings are ranked by priority score (severity x
duration x blast radius x SLA urgency), grouped by remediation action,
and annotated with risk impact percentages and strategic narratives.

This answers the hardest question in security: "I have 1,000 findings;
what do I fix first to make the environment safest?"

Inputs:
  stdin or --in     Assessment JSON from stave apply --format json
  --top             Number of top findings to show (default: 5)
  --format          Output format: text or json (default: text)

Exit Codes:
  0   Roadmap produced
  2   Input error`,
		Example: `  stave apply --format json | stave rank --top 10
  stave rank --in assessment.json --top 5
  stave rank --in assessment.json --format json`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.OutOrStdout(), cmd.ErrOrStderr(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.InputPath, "in", "", "Path to assessment JSON (default: stdin)")
	cmd.Flags().IntVar(&opts.TopN, "top", opts.TopN, "Number of top findings to show")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", opts.Format, "Output format: text or json")
	cmd.Flags().BoolVar(&opts.IncludeAcknowledged, "include-acknowledged", false, "Include acknowledged findings in output")

	return cmd
}

func run(stdout, _ io.Writer, opts *options) error {
	// Read assessment JSON.
	var data []byte
	var err error
	if opts.InputPath != "" {
		data, err = os.ReadFile(opts.InputPath) //nolint:gosec // user-specified path
		if err != nil {
			return fmt.Errorf("read %s: %w", opts.InputPath, err)
		}
	} else {
		data, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("read stdin: %w", err)
		}
	}

	if len(data) == 0 {
		return errors.New("no assessment data provided (pipe from stave apply --format json or use --in)")
	}

	// Parse assessment.
	var assessment report.Assessment
	if jsonErr := json.Unmarshal(data, &assessment); jsonErr != nil {
		return fmt.Errorf("parse assessment: %w", jsonErr)
	}

	// Build roadmap.
	roadmap := apprank.BuildRoadmap(assessment.Findings, assessment.TopExposures, opts.TopN)

	// Output.
	switch opts.Format {
	case "json":
		output, marshalErr := json.MarshalIndent(roadmap, "", "  ")
		if marshalErr != nil {
			return fmt.Errorf("marshal roadmap: %w", marshalErr)
		}
		fmt.Fprintln(stdout, string(output))
	default:
		writeTextRoadmap(stdout, roadmap)
	}

	// Show acknowledged findings if requested.
	if opts.IncludeAcknowledged && len(assessment.AcknowledgedFindings) > 0 {
		fmt.Fprintf(stdout, "\nACKNOWLEDGED FINDINGS (%d)\n", len(assessment.AcknowledgedFindings))
		fmt.Fprintln(stdout, strings.Repeat("-", 50))
		for i := range assessment.AcknowledgedFindings {
			af := &assessment.AcknowledgedFindings[i]
			status := "[ACK]"
			if !af.Valid {
				status = "[INVALID: " + af.InvalidReason + "]"
			}
			fmt.Fprintf(stdout, "  %s  %s on %s\n", status, af.ControlID, af.AssetID)
			if af.Rationale != "" {
				fmt.Fprintf(stdout, "         Rationale: %s\n", af.Rationale)
			}
			if af.AcknowledgedBy != "" {
				fmt.Fprintf(stdout, "         By: %s on %s\n", af.AcknowledgedBy, af.AcknowledgedDate)
			}
			if af.ExpiryDate != "" {
				fmt.Fprintf(stdout, "         Expires: %s\n", af.ExpiryDate)
			}
		}
	}

	return nil
}

func writeTextRoadmap(w io.Writer, rm apprank.Roadmap) {
	if len(rm.Entries) == 0 {
		fmt.Fprintln(w, "No findings to rank.")
		return
	}

	fmt.Fprintf(w, "REMEDIATION STRATEGY (Top %d Actions)\n", len(rm.Entries))
	fmt.Fprintln(w, strings.Repeat("=", 50))

	for idx := range rm.Entries {
		e := &rm.Entries[idx]
		severity := "HIGH"
		if e.PriorityScore >= 500 {
			severity = "CRITICAL"
		} else if e.PriorityScore < 100 {
			severity = "MEDIUM"
		}

		fmt.Fprintf(w, "\n[#%d]  PRIORITY: %.1f (%s)\n", e.Rank, e.PriorityScore, severity)
		if e.IsChainMember {
			fmt.Fprintf(w, "      [ATTACK PATH: %s]  %s on %s\n", e.ChainID, e.ControlID, e.AssetID)
		} else {
			fmt.Fprintf(w, "      %s on %s\n", e.ControlID, e.AssetID)
		}
		if e.Narrative != "" {
			fmt.Fprintf(w, "      %s\n", e.Narrative)
		}
		fmt.Fprintf(w, "      Risk Impact: %.0f%% of total environment risk  |  Changes: %d  |  Confidence: %.0f%%\n",
			e.RiskImpact, len(e.Changes), e.Confidence*100)

		b := &e.Breakdown
		fmt.Fprintf(w, "      Score: base=%d \u00d7 duration=%.1f \u00d7 blast=%.1f \u00d7 exposure=%.1f",
			b.BaseScore, b.DurationFactor, b.BlastMultiplier, b.ExposureMultiplier)
		if e.SLAUrgency > 1.0 {
			fmt.Fprintf(w, " \u00d7 sla=%.1f", e.SLAUrgency)
		}
		fmt.Fprintln(w)

		if e.FixAction != "" {
			action := e.FixAction
			if len(action) > 80 {
				action = action[:77] + "..."
			}
			fmt.Fprintf(w, "      Fix: %s\n", action)
		}
	}

	if len(rm.Bundles) > 0 {
		fmt.Fprintf(w, "\nREMEDIATION BUNDLES (Highest ROI)\n")
		fmt.Fprintln(w, strings.Repeat("-", 40))
		for i, b := range rm.Bundles {
			action := b.Action
			if len(action) > 60 {
				action = action[:57] + "..."
			}
			fmt.Fprintf(w, "  %d. Resolve %d findings (risk reduced: %.0f, efficiency: %.1f)\n",
				i+1, b.FindingCount, b.TotalRiskReduced, b.Efficiency)
			fmt.Fprintf(w, "     %s\n", action)
		}
	}
}
