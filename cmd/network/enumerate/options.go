package enumerate

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/platform/fsutil"
)

type options struct {
	observations string
	port         int
	format       string
}

func addFlags(cmd *cobra.Command, o *options) {
	f := cmd.Flags()
	f.StringVarP(&o.observations, "observations", "o", "", "path to observations directory (required)")
	f.IntVar(&o.port, "port", 22, "port to enumerate (default: 22)")
	f.StringVarP(&o.format, "format", "f", "text", "output format: json, text")
	_ = cmd.MarkFlagRequired("observations")
}

func (o *options) Prepare(_ *cobra.Command) error {
	o.observations = fsutil.CleanUserPath(o.observations)
	if _, err := NewRenderer(o.format); err != nil {
		return err
	}
	return nil
}
