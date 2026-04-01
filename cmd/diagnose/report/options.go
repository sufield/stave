package report

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// options holds the raw CLI flag values for the report command.
type options struct {
	InputFile    string
	Format       string
	TemplateFile string
}

// BindFlags attaches the options to a Cobra command.
func (o *options) BindFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVarP(&o.InputFile, "in", "i", "", "Path to evaluation JSON file (required)")
	f.StringVarP(&o.Format, "format", "f", o.Format, "Output format (text|json)")
	f.StringVar(&o.TemplateFile, "template-file", "", "Path to custom Go template")
	_ = cmd.MarkFlagRequired("in")
	_ = cmd.RegisterFlagCompletionFunc("format", cliflags.CompleteFixed(cliflags.FormatsTextJSON...))
}

// Prepare normalizes paths. Called from PreRunE.
func (o *options) Prepare(_ *cobra.Command) error {
	o.InputFile = fsutil.CleanUserPath(o.InputFile)
	o.TemplateFile = fsutil.CleanUserPath(o.TemplateFile)
	return nil
}

// resolveFormat resolves the output format using the command context.
func (o *options) resolveFormat(cmd *cobra.Command) (appcontracts.OutputFormat, error) {
	return compose.ResolveFormatValue(cmd, o.Format)
}
