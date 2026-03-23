package doctor

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/cli/ui"
)

// options holds the raw CLI flag values for the doctor command.
type options struct {
	Format string
}

// BindFlags attaches the options to a Cobra command.
func (o *options) BindFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&o.Format, "format", "f", o.Format, "Output format: text or json")
}

// Prepare is a no-op for doctor; included for pattern consistency.
// Called from PreRunE.
func (o *options) Prepare(_ *cobra.Command) error {
	return nil
}

// resolveFormat resolves the output format using the command context.
func (o *options) resolveFormat(cmd *cobra.Command) (ui.OutputFormat, error) {
	return compose.ResolveFormatValue(cmd, o.Format)
}
