package nep

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/stave"
)

type resourceOpts struct {
	Snapshot       string
	ResourceARN    string
	Format         string
	Actions        string
	Classification string
	ShowDesignated bool
}

func newResourceCmd() *cobra.Command {
	opts := &resourceOpts{Format: "table", Classification: "phi"}

	cmd := &cobra.Command{
		Use:   "resource",
		Short: "Show who has effective access to a resource",
		Long: `Show all principals with resolved effective access to a specific
resource ARN, with access path attribution (identity-based, resource
policy, or both).

By default shows only non-designated principals. Use --all to include
designated principals.

Exit Codes:
  0   No non-designated access to the resource
  1   Non-designated principals have access (PHI violation)
  3   Incomplete resolution
  4   Internal error

Examples:
  stave nep resource --snapshot obs.json \
    --resource arn:aws:s3:::phi-patient-records

  stave nep resource --snapshot obs.json \
    --resource arn:aws:s3:::phi-records --all

  stave nep resource --snapshot obs.json \
    --resource arn:aws:s3:::phi-records --format dot | dot -Tpng > access.png`,
		Example: `  stave nep resource --snapshot obs.json --resource arn:aws:s3:::phi-records
  stave nep resource --snapshot obs.json --resource arn:aws:s3:::phi-records --all --format dot`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, warnings, hasFindings, err := stave.ResolveResourceAccess(stave.NepResourceConfig{
				Snapshot:       opts.Snapshot,
				ResourceARN:    opts.ResourceARN,
				Format:         opts.Format,
				Actions:        opts.Actions,
				Classification: opts.Classification,
				ShowDesignated: opts.ShowDesignated,
			})
			if err != nil {
				return err //nolint:wrapcheck // facade already wrapped; preserve exit 4.
			}
			for _, warn := range warnings {
				fmt.Fprintln(cmd.ErrOrStderr(), warn)
			}
			if _, werr := cmd.OutOrStdout().Write(out); werr != nil {
				return fmt.Errorf("write resource output: %w", werr)
			}
			if hasFindings {
				return ui.ErrSecurityAuditFindings
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.Snapshot, "snapshot", "", "path to snapshot file (required)")
	cmd.Flags().StringVar(&opts.ResourceARN, "resource", "", "resource ARN to query (required)")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "table", "output format: table | json | dot")
	cmd.Flags().StringVar(&opts.Actions, "actions", "", "comma-separated action filter")
	cmd.Flags().StringVar(&opts.Classification, "classification", "phi", "data classification tag value to filter resources")
	cmd.Flags().BoolVar(&opts.ShowDesignated, "all", false, "show all principals including designated")
	cmd.Flags().BoolVar(&opts.ShowDesignated, "show-designated", false, "show designated principals (alias for --all)")

	cliflags.MustMarkRequired(cmd, "snapshot")
	cliflags.MustMarkRequired(cmd, "resource")

	return cmd
}
