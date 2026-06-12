package nep

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/pkg/stave"
)

type principalOpts struct {
	Snapshot      string
	PrincipalARN  string
	Format        string
	ShowDenied    bool
	ShowChains    bool
	FilterService string
}

func newPrincipalCmd() *cobra.Command {
	opts := &principalOpts{Format: "table"}

	cmd := &cobra.Command{
		Use:   "principal",
		Short: "Resolve permissions for a specific principal ARN",
		Long: `Resolve and display the net effective permissions for a single IAM
principal after all policy layers are applied.

Shows: effective allows, SCP ceiling, permission boundary constraint,
role chains, and privilege classification.

Exit Codes:
  0   Resolution complete, no critical findings
  1   Principal has admin-equivalent or escalation findings
  3   Incomplete resolution (snapshot data missing)
  4   Internal error

Examples:
  stave nep principal --snapshot obs.json \
    --principal arn:aws:iam::123456789012:role/data-pipeline

  stave nep principal --snapshot obs.json \
    --principal arn:aws:iam::123456789012:role/app \
    --format json --show-chains`,
		Example:       `  stave nep principal --snapshot obs.json --principal arn:aws:iam::123:role/app`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, err := stave.ResolvePrincipal(stave.NepPrincipalConfig{
				Snapshot:      opts.Snapshot,
				PrincipalARN:  opts.PrincipalARN,
				Format:        opts.Format,
				ShowDenied:    opts.ShowDenied,
				ShowChains:    opts.ShowChains,
				FilterService: opts.FilterService,
			})
			if err != nil {
				return err //nolint:wrapcheck // facade already wrapped; preserve exit 4.
			}
			if _, werr := cmd.OutOrStdout().Write(out); werr != nil {
				return fmt.Errorf("write principal output: %w", werr)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.Snapshot, "snapshot", "", "path to snapshot file (required)")
	cmd.Flags().StringVar(&opts.PrincipalARN, "principal", "", "principal ARN to resolve (required)")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "table", "output format: table | json")
	cmd.Flags().BoolVar(&opts.ShowDenied, "show-denied", false, "include denied actions")
	cmd.Flags().BoolVar(&opts.ShowChains, "show-chains", false, "include role chain detail")
	cmd.Flags().StringVar(&opts.FilterService, "filter-service", "", "filter to a specific service prefix")

	cliflags.MustMarkRequired(cmd, "snapshot")
	cliflags.MustMarkRequired(cmd, "principal")

	return cmd
}
