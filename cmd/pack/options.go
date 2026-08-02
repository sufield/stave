package pack

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
)

// options holds shared flags for the pack subcommands.
type options struct {
	format      string
	controls    string
	controlsSet bool
}

func addCommonFlags(cmd *cobra.Command, o *options) {
	f := cmd.Flags()
	f.StringVarP(&o.format, "format", "f", "text", "output format: text, json")
	f.StringVarP(&o.controls, "controls", "i", "", "control definitions directory (default: built-in catalog)")
}

// Prepare validates flags at the CLI boundary (PreRunE).
func (o *options) Prepare(cmd *cobra.Command) error {
	o.controlsSet = cmd.Flags().Changed("controls")
	if _, err := NewRenderer(o.format); err != nil {
		return &ui.UserError{Err: err}
	}
	return nil
}
