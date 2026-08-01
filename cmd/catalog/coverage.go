package catalog

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/stave"
)

func newCoverageCmd() *cobra.Command {
	opts := &options{
		Format: "text",
	}
	cmd := &cobra.Command{
		Use:   "coverage",
		Short: "Show per-service control coverage",
		Long: `Coverage maps the catalog against services, showing how many
controls and categories each service has and which asset types they
apply to.

Inputs:
  --format F       text (default) | json
  --controls DIR   Control catalog directory (default: controls)

Exit codes:
  0   Success
  4   Internal error
`,
		Example: `  stave catalog coverage
  stave catalog coverage --format json | jq '.services[] | select(.controls > 10)'`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if opts.Format != "json" && opts.Format != "text" && opts.Format != "" {
				return &ui.UserError{Err: fmt.Errorf("--format must be text | json (got %q)", opts.Format)}
			}
			out, err := stave.RenderCatalogCoverage(cmd.Context(), stave.CatalogCoverageOptions{
				ControlsDir: opts.ControlsDir,
				Format:      opts.Format,
			})
			if err != nil {
				return err //nolint:wrapcheck // facade already wrapped; preserve exit 4.
			}
			_, err = cmd.OutOrStdout().Write(out)
			return err
		},
	}
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "text", "output format: text | json")
	cmd.Flags().StringVarP(&opts.ControlsDir, "controls", "i", "", "control catalog directory (default: embedded catalog)")
	return cmd
}
