// Package mapcmd implements the 'stave map' command for ATT&CK coverage analysis.
package mapcmd

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/stave"
)

type options struct {
	OutputFile  string
	ControlsDir string
	Format      string
	MinControls int
	NoPager     bool
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
  stave map --output assessment.json --format navigator > layer.json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Page only the human table to a terminal — json/navigator/markdown
			// are machine formats redirected with a shell pipe.
			pageable := !opts.NoPager && opts.Format == "table"
			pw, closePager := ui.NewPager(cmd.Context(), cmd.OutOrStdout(), pageable)
			err := runMap(cmd.Context(), pw, opts)
			if cerr := closePager(); cerr != nil && err == nil {
				err = cerr
			}
			return err
		},
	}

	cmd.Flags().StringVar(&opts.OutputFile, "output", "", "path to out.v0.1.json for posture overlay")
	cmd.Flags().StringVarP(&opts.ControlsDir, "controls", "i", "", "path to controls directory (default: embedded catalog)")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "table", "output format: table | json | navigator | markdown")
	cmd.Flags().BoolVar(&opts.NoPager, "no-pager", false, "never page output, even on a terminal")
	cmd.Flags().IntVar(&opts.MinControls, "min-controls", 2, "thin coverage threshold")

	return cmd
}

func runMap(ctx context.Context, stdout io.Writer, opts *options) error {
	// Read the optional posture-overlay assessment (fsutil is an exempt
	// command-side helper); the facade parses + builds + renders.
	var assessmentData []byte
	if opts.OutputFile != "" {
		data, readErr := fsutil.ReadFileLimited(opts.OutputFile)
		if readErr != nil {
			return fmt.Errorf("read assessment: %w", readErr)
		}
		assessmentData = data
	}

	out, err := stave.MapAttackCoverage(ctx, fsutil.CleanUserPath(opts.ControlsDir), opts.MinControls, assessmentData, opts.Format)
	if err != nil {
		return err //nolint:wrapcheck // facade already wrapped; all map errors are exit-4 plain.
	}
	if _, werr := stdout.Write(out); werr != nil {
		return fmt.Errorf("write coverage map: %w", werr)
	}
	return nil
}
