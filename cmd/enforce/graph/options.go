package graph

import (
	"fmt"

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
	_ = cmd.RegisterFlagCompletionFunc("format", cliflags.CompleteFixed("dot", "json"))
}

// ToConfig validates flags and converts them into a typed runner configuration.
func (o *coverageOptions) ToConfig(cmd *cobra.Command) (config, error) {
	format, err := ParseFormat(o.FormatRaw)
	if err != nil {
		return config{}, fmt.Errorf("invalid format: %w", err)
	}
	gf := cliflags.GetGlobalFlags(cmd)
	return config{
		ControlsDir:     fsutil.CleanUserPath(o.ControlsDir),
		ObservationsDir: fsutil.CleanUserPath(o.ObsDir),
		Format:          format,
		AllowUnknown:    o.AllowUnknown,
		Sanitizer:       gf.GetSanitizer(),
		Stdout:          cmd.OutOrStdout(),
	}, nil
}
