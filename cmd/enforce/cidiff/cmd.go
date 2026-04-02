package cidiff

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/reporting"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// Deps groups the infrastructure implementations for the ci diff command.
type Deps struct {
	UseCaseDeps reporting.CIDiffDeps
}

// options holds the raw CLI flag values for the ci diff command.
type options struct {
	CurrentPath  string
	BaselinePath string
	FailOnNew    bool
}

// NewCmd constructs the diff command.
func NewCmd(deps Deps) *cobra.Command {
	opts := &options{FailOnNew: true}

	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Compare two evaluations and report new findings",
		Long: `Diff compares a current evaluation against a baseline evaluation and
reports newly introduced and resolved findings.

Use this in CI to fail PRs only when new violations are introduced.

Exit Codes:
  0   - Success
  2   - Input error
  3   - New findings detected (with --fail-on-new)
  4   - Internal error` + metadata.OfflineHelpSuffix,
		Example: `  stave ci diff --current pr-evaluation.json --baseline main-evaluation.json
  stave ci diff --current pr-evaluation.json --baseline main-evaluation.json --fail-on-new`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			req := reporting.CIDiffRequest{
				CurrentPath:  opts.CurrentPath,
				BaselinePath: opts.BaselinePath,
				FailOnNew:    opts.FailOnNew,
			}

			resp, err := reporting.CIDiff(cmd.Context(), req, deps.UseCaseDeps)
			if err != nil {
				return err
			}

			if renderErr := jsonutil.WriteIndented(cmd.OutOrStdout(), resp); renderErr != nil {
				return renderErr
			}

			if req.FailOnNew && resp.HasNew {
				return ui.ErrViolationsFound
			}
			return nil
		},
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
