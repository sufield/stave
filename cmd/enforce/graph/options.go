package graph

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// coverageOptions holds the raw CLI flag values for the coverage subcommand.
type coverageOptions struct {
	ControlsDir     string
	ObservationsDir string
	Format          string
	AllowUnknown    bool
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
	f.BoolVar(&o.AllowUnknown, "allow-unknown-input", o.AllowUnknown, cliflags.WithDynamicDefaultHelp("Allow observations with unknown or missing source types"))
	_ = cmd.RegisterFlagCompletionFunc("format", cliflags.CompleteFixed("dot", "json"))
}

// toConfig validates flags and converts them into a typed runner configuration.
func toConfig(o *coverageOptions, gf cliflags.GlobalFlags, stdout io.Writer) (config, error) {
	format, err := ParseFormat(o.Format)
	if err != nil {
		return config{}, &ui.UserError{Err: fmt.Errorf("invalid format: %w", err)}
	}
	return config{
		ControlsDir:     fsutil.CleanUserPath(o.ControlsDir),
		ObservationsDir: fsutil.CleanUserPath(o.ObservationsDir),
		Format:          format,
		AllowUnknown:    o.AllowUnknown,
		Sanitizer:       gf.GetSanitizer(),
		Stdout:          stdout,
	}, nil
}
