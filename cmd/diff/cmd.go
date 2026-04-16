// Package diff implements the 'stave diff' command for catalog
// upgrade impact analysis.
package diff

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	appdiff "github.com/sufield/stave/internal/app/catalogdiff"
	"github.com/sufield/stave/internal/cli/ui"
)

type options struct {
	CatalogBefore string
	CatalogAfter  string
	Format        string
}

// NewCmd constructs the diff command.
func NewCmd(newCtlRepo compose.CtlRepoFactory) *cobra.Command {
	opts := &options{Format: "table"}

	cmd := &cobra.Command{
		Use:   "catalog-diff",
		Short: "Compare two control catalog versions",
		Long: `Analyze the impact of upgrading between two control catalog versions.
Shows new controls, removed controls, and severity changes.

Exit Codes:
  0   Diff produced
  2   Invalid input`,
		Example:       `  stave diff --catalog-before ./controls-v1/ --catalog-after ./controls-v2/`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDiff(cmd.Context(), cmd.OutOrStdout(), opts, newCtlRepo)
		},
	}

	cmd.Flags().StringVar(&opts.CatalogBefore, "catalog-before", "", "path to before catalog (required)")
	cmd.Flags().StringVar(&opts.CatalogAfter, "catalog-after", "", "path to after catalog (required)")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "table", "output format: table | json")

	_ = cmd.MarkFlagRequired("catalog-before")
	_ = cmd.MarkFlagRequired("catalog-after")

	return cmd
}

func runDiff(ctx context.Context, stdout io.Writer, opts *options, newCtlRepo compose.CtlRepoFactory) error {
	repo, err := newCtlRepo()
	if err != nil {
		return fmt.Errorf("create control loader: %w", err)
	}

	before, err := repo.LoadControls(ctx, opts.CatalogBefore)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("load before catalog: %w", err)}
	}

	after, loadErr := repo.LoadControls(ctx, opts.CatalogAfter)
	if loadErr != nil {
		return &ui.UserError{Err: fmt.Errorf("load after catalog: %w", loadErr)}
	}

	delta := appdiff.Compute(before, after)

	switch opts.Format {
	case "json":
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(delta)
	default:
		_, _ = fmt.Fprint(stdout, appdiff.FormatTable(delta))
		return nil
	}
}
