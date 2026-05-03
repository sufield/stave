// Package mapcmd implements the 'stave map' command for ATT&CK coverage analysis.
package mapcmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	appcoverage "github.com/sufield/stave/internal/app/coverage"
	"github.com/sufield/stave/internal/core/report"
	"github.com/sufield/stave/internal/platform/fsutil"
)

type options struct {
	OutputFile  string
	ControlsDir string
	Format      string
	OutPath     string
	MinControls int
}

// NewCmd constructs the map command.
func NewCmd() *cobra.Command {
	opts := &options{Format: "table", ControlsDir: "controls", MinControls: 2}

	cmd := &cobra.Command{
		Use:   "map",
		Short: "ATT&CK tactic coverage and gap analysis",
		Long: `Produce a MITRE ATT&CK tactic coverage map from the control catalog.
Optionally overlay current posture from assessment output.

Exit Codes:
  0   Map produced
  2   Invalid input
  4   Internal error`,
		Example: `  stave map
  stave map --output assessment.json --format navigator --out layer.json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runMap(cmd.Context(), cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.OutputFile, "output", "", "path to out.v0.1.json for posture overlay")
	cmd.Flags().StringVarP(&opts.ControlsDir, "controls", "i", "controls", "path to controls directory")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "table", "output format: table | json | navigator | markdown")
	cmd.Flags().StringVar(&opts.OutPath, "out", "", "write to file instead of stdout")
	cmd.Flags().IntVar(&opts.MinControls, "min-controls", 2, "thin coverage threshold")

	return cmd
}

func runMap(ctx context.Context, stdout io.Writer, opts *options) error {
	f := compose.DefaultFactories()
	ctlRepo, err := f.NewCtlRepo()
	if err != nil {
		return fmt.Errorf("create control loader: %w", err)
	}
	controls, err := ctlRepo.LoadControls(ctx, fsutil.CleanUserPath(opts.ControlsDir))
	if err != nil {
		return fmt.Errorf("load controls: %w", err)
	}

	input := appcoverage.BuildInput{
		Controls:    controls,
		MinControls: opts.MinControls,
	}

	// Optional posture overlay.
	if opts.OutputFile != "" {
		data, readErr := fsutil.ReadFileLimited(opts.OutputFile)
		if readErr != nil {
			return fmt.Errorf("read assessment: %w", readErr)
		}
		var assessment report.Assessment
		if jsonErr := json.Unmarshal(data, &assessment); jsonErr != nil {
			return fmt.Errorf("parse assessment: %w", jsonErr)
		}
		input.Findings = assessment.Findings
	}

	coverageReport := appcoverage.Build(input)

	out := stdout
	if opts.OutPath != "" {
		outFile, createErr := os.Create(opts.OutPath)
		if createErr != nil {
			return fmt.Errorf("create output: %w", createErr)
		}
		defer outFile.Close()
		out = outFile
	}

	switch opts.Format {
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(coverageReport)
	case "navigator":
		layer := appcoverage.NavigatorLayer(coverageReport)
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(layer)
	case "markdown":
		writeMarkdown(out, coverageReport)
		return nil
	default:
		writeTable(out, coverageReport)
		return nil
	}
}

func writeTable(w io.Writer, r *appcoverage.CoverageReport) {
	fmt.Fprintf(w, "MITRE ATT&CK COVERAGE MAP\n")
	fmt.Fprintf(w, "Controls: %d analyzed, %d annotated, %d unannotated\n\n",
		r.ControlsAnalyzed, r.ControlsAnnotated, r.ControlsUnannotated)

	// Gaps first.
	hasGaps := false
	for i := range r.Tactics {
		if r.Tactics[i].IsGap() {
			if !hasGaps {
				fmt.Fprintln(w, "COVERAGE GAPS")
				fmt.Fprintln(w, strings.Repeat("-", 70))
				hasGaps = true
			}
			tc := &r.Tactics[i]
			fmt.Fprintf(w, "  %-22s %-7s %3d controls  %s\n",
				tc.TacticName, tc.TacticID, tc.ControlCount, tc.DisplayStatus())
		}
	}
	if hasGaps {
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "FULL TACTIC COVERAGE")
	fmt.Fprintln(w, strings.Repeat("-", 70))
	for i := range r.Tactics {
		tc := &r.Tactics[i]
		passingStr := "—"
		if tc.PassingCount != nil {
			passingStr = fmt.Sprintf("%d/%d", *tc.PassingCount, tc.ControlCount)
		}
		fmt.Fprintf(w, "  %-22s %-7s %3d controls  %s\n",
			tc.TacticName, tc.TacticID, tc.ControlCount, passingStr)
	}

	fmt.Fprintf(w, "\nSummary: %d/%d tactics covered, %d thin, %d gaps\n",
		r.Summary.TacticsCovered, r.Summary.TacticsTotal, r.Summary.TacticsThin, r.Summary.TacticsNoCoverage)
}

func writeMarkdown(w io.Writer, r *appcoverage.CoverageReport) {
	fmt.Fprintln(w, "# MITRE ATT&CK Coverage Report")
	fmt.Fprintf(w, "Controls: %d | Annotated: %d\n\n", r.ControlsAnalyzed, r.ControlsAnnotated)

	fmt.Fprintln(w, "| Tactic | ID | Controls | Status |")
	fmt.Fprintln(w, "|---|---|---|---|")
	for i := range r.Tactics {
		tc := &r.Tactics[i]
		fmt.Fprintf(w, "| %s | %s | %d | %s |\n",
			tc.TacticName, tc.TacticID, tc.ControlCount, tc.Status)
	}
}
