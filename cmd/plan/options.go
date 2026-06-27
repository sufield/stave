package plan

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
)

var (
	errNoInput   = errors.New("provide --services (e.g. iam,s3) or --pack <name>")
	errBothInput = errors.New("use --services or --pack, not both")
)

type options struct {
	services    []string
	pack        string
	format      string
	controls    string
	controlsSet bool
}

func addFlags(cmd *cobra.Command, o *options) {
	f := cmd.Flags()
	f.StringSliceVar(&o.services, "services", nil,
		"AWS services to preview (comma-separated), e.g. iam,s3,ec2")
	f.StringVar(&o.pack, "pack", "", "preview a named pack instead of services")
	f.StringVarP(&o.format, "format", "f", "text", "output format: text, json")
	f.StringVarP(&o.controls, "controls", "i", "controls",
		"control definitions directory (default: built-in catalog)")
}

func (o *options) Prepare(cmd *cobra.Command) error {
	o.controlsSet = cmd.Flags().Changed("controls")
	hasServices, hasPack := len(o.services) > 0, o.pack != ""
	switch {
	case !hasServices && !hasPack:
		return &ui.UserError{Err: errNoInput}
	case hasServices && hasPack:
		return &ui.UserError{Err: errBothInput}
	}
	if _, err := NewRenderer(o.format); err != nil {
		return &ui.UserError{Err: err}
	}
	return nil
}
