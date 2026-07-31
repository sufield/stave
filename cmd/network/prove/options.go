package prove

import (
	"fmt"
	"slices"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
)

var validProperties = []string{"bastion-ssh"}

type options struct {
	observations string
	property     string
	port         int
	format       string
}

func addFlags(cmd *cobra.Command, o *options) {
	f := cmd.Flags()
	f.StringVarP(&o.observations, "observations", "o", "", "path to observations directory (required)")
	f.StringVar(&o.property, "property", "bastion-ssh", "safety property to verify: bastion-ssh")
	f.IntVar(&o.port, "port", 22, "port to verify (default: 22)")
	f.StringVarP(&o.format, "format", "f", "text", "output format: json, text")
	_ = cmd.MarkFlagRequired("observations")
}

func (o *options) Prepare(_ *cobra.Command) error {
	o.observations = fsutil.CleanUserPath(o.observations)
	if !slices.Contains(validProperties, o.property) {
		return &ui.UserError{
			Err: fmt.Errorf("unknown --property %q (valid: bastion-ssh)", o.property),
		}
	}
	if _, err := NewRenderer(o.format); err != nil {
		return &ui.UserError{Err: err}
	}
	return nil
}
