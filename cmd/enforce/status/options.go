package status

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// options holds the raw CLI flag values for the status command.
type options struct {
	Dir    string
	Format string
}

// BindFlags attaches the options to a Cobra command.
func (o *options) BindFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVarP(&o.Dir, "dir", "d", o.Dir, "Directory to inspect for Stave project context")
	f.StringVarP(&o.Format, "format", "f", o.Format, "Output format: text or json")
}

// Prepare normalizes paths and resolves format. Called from PreRunE.
func (o *options) Prepare(_ *cobra.Command) error {
	o.Dir = fsutil.CleanUserPath(o.Dir)
	return nil
}

// resolveFormat resolves the output format using the command context.
func (o *options) resolveFormat(cmd *cobra.Command) (ui.OutputFormat, error) {
	return compose.ResolveFormatValue(cmd, o.Format)
}
