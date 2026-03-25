package graph

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// coverageOptions holds the raw CLI flag values for the coverage subcommand.
type coverageOptions struct {
	ControlsDir  string
	ObsDir       string
	FormatRaw    string
	AllowUnknown bool
}

// BindFlags attaches the options to a Cobra command.
func (o *coverageOptions) BindFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVarP(&o.ControlsDir, "controls", "i", o.ControlsDir, "Path to control definitions directory")
	f.StringVarP(&o.ObsDir, "observations", "o", o.ObsDir, "Path to observation snapshots directory")
	f.StringVarP(&o.FormatRaw, "format", "f", o.FormatRaw, "Output format: dot or json")
	f.BoolVar(&o.AllowUnknown, "allow-unknown-input", o.AllowUnknown, cliflags.WithDynamicDefaultHelp("Allow observations with unknown or missing source types"))
}

// Prepare normalizes paths. Called from PreRunE.
func (o *coverageOptions) Prepare(_ *cobra.Command) error {
	o.ControlsDir = fsutil.CleanUserPath(o.ControlsDir)
	o.ObsDir = fsutil.CleanUserPath(o.ObsDir)
	return nil
}
