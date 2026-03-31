package status

import (
	"io"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
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

// cmdIO holds values extracted from *cobra.Command in RunE.
type cmdIO struct {
	Stdout        io.Writer
	Stderr        io.Writer
	FormatChanged bool
}

// toConfig validates flags and returns a typed config.
// Standalone function — does not depend on cobra.
func toConfig(o *options, cio cmdIO) (config, error) {
	format, err := compose.ResolveFormatValuePure(o.Format, cio.FormatChanged, false)
	if err != nil {
		return config{}, err
	}
	return config{
		Dir:    fsutil.CleanUserPath(o.Dir),
		Format: format,
		Stdout: cio.Stdout,
		Stderr: cio.Stderr,
	}, nil
}
