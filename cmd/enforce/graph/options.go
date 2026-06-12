package graph

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
)

// coverageOptions holds the raw CLI flag values for the coverage subcommand.
type coverageOptions struct {
	ControlsDir     string
	ObservationsDir string
	Format          string
}

func defaultCoverageOptions() *coverageOptions {
	return &coverageOptions{
		ControlsDir:     cliflags.DefaultControlsDir,
		ObservationsDir: "observations",
		Format:          "dot",
	}
}

// BindFlags attaches the options to a Cobra command.
func (o *coverageOptions) BindFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVarP(&o.ControlsDir, "controls", "i", o.ControlsDir, "Path to control definitions directory")
	f.StringVarP(&o.ObservationsDir, "observations", "o", o.ObservationsDir, "Path to observation snapshots directory")
	f.StringVarP(&o.Format, "format", "f", o.Format, "Output format: dot or json")
	_ = cmd.RegisterFlagCompletionFunc("format", cliflags.CompleteFixed("dot", "json"))
}
