package discover

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
)

// options holds flags for `stave discover`.
type options struct {
	services    []string
	format      string
	controls    string
	controlsSet bool
	policy      bool
}

func addFlags(cmd *cobra.Command, o *options) {
	f := cmd.Flags()
	f.StringSliceVar(&o.services, "services", nil,
		"AWS services in use (comma-separated), e.g. iam,s3,ec2,lambda,cloudtrail")
	f.StringVarP(&o.format, "format", "f", "text", "output format: text, json")
	f.StringVarP(&o.controls, "controls", "i", "",
		"control definitions directory (default: built-in catalog)")
	f.BoolVar(&o.policy, "policy", false,
		"output a least-privilege IAM policy document (JSON) instead of the collection manifest")
}

// Prepare validates flags at the CLI boundary (PreRunE).
func (o *options) Prepare(cmd *cobra.Command) error {
	o.controlsSet = cmd.Flags().Changed("controls")
	if len(o.services) == 0 {
		return &ui.UserError{Err: errNoServices}
	}
	if _, err := NewRenderer(o.format); err != nil {
		return &ui.UserError{Err: err}
	}
	return nil
}
