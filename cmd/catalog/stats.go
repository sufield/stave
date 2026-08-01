package catalog

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/stave"
)

func newStatsCmd() *cobra.Command {
	opts := &options{
		Format: "text",
	}
	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Print aggregate catalog statistics",
		Long: `Stats computes aggregate counts from the control catalog: total
controls, services, chains, operational features, severity breakdown,
and a per-service summary table.

Inputs:
  --format F       text (default) | json
  --controls DIR   Control catalog directory (default: controls)
  --chains DIR     Chain catalog directory (default: chains)

Exit codes:
  0   Success
  4   Internal error
`,
		Example: `  stave catalog stats
  stave catalog stats --format json | jq '.severity'`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if opts.Format != "json" && opts.Format != "text" && opts.Format != "" {
				return &ui.UserError{Err: fmt.Errorf("--format must be text | json (got %q)", opts.Format)}
			}
			out, err := stave.RenderCatalogStats(cmd.Context(), stave.CatalogStatsOptions{
				ControlsDir: opts.ControlsDir,
				ChainsDir:   opts.ChainsDir,
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
	cmd.Flags().StringVar(&opts.ChainsDir, "chains", "", "chain catalog directory (default: embedded chains)")
	return cmd
}
