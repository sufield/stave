package doctor

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
)

// options holds the raw CLI flag values for the doctor command.
type options struct {
	Format        string
	formatChanged bool
}

// BindFlags attaches the options to a Cobra command.
func (o *options) BindFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&o.Format, "format", "f", o.Format, "Output format: text or json")
}

// Prepare captures flag-changed state. Called from PreRunE.
func (o *options) Prepare(cmd *cobra.Command) error {
	o.formatChanged = cmd.Flags().Changed("format")
	return nil
}

// resolveFormat resolves the output format without needing *cobra.Command.
func (o *options) resolveFormat() (appcontracts.OutputFormat, error) {
	return compose.ResolveFormatValuePure(o.Format, o.formatChanged, false)
}
