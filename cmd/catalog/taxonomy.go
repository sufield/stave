package catalog

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/stave"
)

func newTaxonomyCmd() *cobra.Command {
	opts := &options{
		Format: "text",
	}
	cmd := &cobra.Command{
		Use:   "taxonomy",
		Short: "List taxonomy categories with control counts",
		Long: `Taxonomy lists all security concept categories found in the control
catalog, with the number of controls tagged in each category.

Inputs:
  --format F       text (default) | json
  --controls DIR   Control catalog directory (default: controls)

Exit codes:
  0   Success
  4   Internal error
`,
		Example: `  stave catalog taxonomy
  stave catalog taxonomy --format json | jq '.[] | select(.count > 100)'`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if opts.Format != "json" && opts.Format != "text" && opts.Format != "" {
				return &ui.UserError{Err: fmt.Errorf("--format must be text | json (got %q)", opts.Format)}
			}
			out, err := stave.RenderTaxonomy(cmd.Context(), stave.TaxonomyOptions{
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
