package cmd

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/diagnose/artifacts"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/stave"
)

// newControlsCmd builds the `controls` command tree, including the
// `controls diff` catalog-comparison subcommand.
func newControlsCmd(newCtlRepo compose.CtlRepoFactory) *cobra.Command {
	cmd := artifacts.NewControlsCmd(newCtlRepo)
	cmd.AddCommand(newCatalogDiffCmd())
	return cmd
}

func newCatalogDiffCmd() *cobra.Command {
	var (
		catalogBefore string
		catalogAfter  string
		format        string
	)
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Compare two control catalog versions",
		Long: `Compare two control catalog directories and report new/removed controls
and severity changes between versions.

Inputs:
  --before PATH   Earlier catalog directory (required)
  --after PATH    Later catalog directory (required)
  --format, -f    Output format: text | json (default: text)

Exit Codes:
  0   Diff produced
  2   Invalid input`,
		Example:       `  stave controls diff --before ./controls-v1/ --after ./controls-v2/`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if catalogBefore == "" || catalogAfter == "" {
				return &ui.UserError{Err: errors.New("--before and --after are required")}
			}
			out, err := stave.DiffCatalogs(cmd.Context(), catalogBefore, catalogAfter, format)
			if err != nil {
				if errors.Is(err, stave.ErrInvalidInput) {
					return &ui.UserError{Err: err}
				}
				return err //nolint:wrapcheck // facade already wrapped; preserve the exit-4 message verbatim.
			}
			_, werr := cmd.OutOrStdout().Write(out)
			return werr
		},
	}
	cmd.Flags().StringVar(&catalogBefore, "before", "", "path to earlier catalog directory (required)")
	cmd.Flags().StringVar(&catalogAfter, "after", "", "path to later catalog directory (required)")
	cmd.Flags().StringVarP(&format, "format", "f", "text", "output format: text | json")
	return cmd
}
