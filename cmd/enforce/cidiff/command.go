package cidiff

import (
	"github.com/spf13/cobra"
	"github.com/sufield/stave/internal/metadata"
)

func NewCmd() *cobra.Command {
	opts := &options{FailOnNew: true}

	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Compare two evaluations and report new findings",
		Long: `Diff compares a current evaluation against a baseline evaluation and
reports newly introduced and resolved findings.

Use this in CI to fail PRs only when new violations are introduced.

Example:
  stave ci diff --current pr-evaluation.json --baseline main-evaluation.json
  stave ci diff --current pr-evaluation.json --baseline main-evaluation.json --fail-on-new` + metadata.OfflineHelpSuffix,
		Args:          cobra.NoArgs,
		RunE:          func(cmd *cobra.Command, _ []string) error { return run(cmd.OutOrStdout(), opts) },
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVar(&opts.CurrentPath, "current", "", "Path to current evaluation JSON (required)")
	cmd.Flags().StringVar(&opts.BaselinePath, "baseline", "", "Path to baseline evaluation JSON (required)")
	cmd.Flags().BoolVar(&opts.FailOnNew, "fail-on-new", opts.FailOnNew, "Return exit code 3 when new findings are detected")
	_ = cmd.MarkFlagRequired("current")
	_ = cmd.MarkFlagRequired("baseline")
	return cmd
}
