package cidiff

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/metadata"
	"github.com/sufield/stave/pkg/stave"
)

// options holds the raw CLI flag values for the ci diff command.
type options struct {
	CurrentPath  string
	BaselinePath string
	FailOnNew    bool
	Format       string
}

// NewCmd constructs the diff command.
func NewCmd() *cobra.Command {
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
  stave ci diff --current pr-evaluation.json --baseline main-evaluation.json --format text
  stave ci diff --current pr-evaluation.json --baseline main-evaluation.json --fail-on-new`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			renderer, rerr := NewRenderer(opts.Format)
			if rerr != nil {
				return &ui.UserError{Err: rerr}
			}
			resp, err := stave.CIDiffResult(cmd.Context(), opts.CurrentPath, opts.BaselinePath, opts.FailOnNew)
			if err != nil {
				return err //nolint:wrapcheck // facade already wrapped ("run CI diff"); preserve exit 4.
			}
			if rerr := renderer.Render(cmd.OutOrStdout(), resp); rerr != nil {
				return fmt.Errorf("write output: %w", rerr)
			}
			if opts.FailOnNew && resp.HasNew {
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
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "json", "Output format (json, text)")
	_ = cmd.MarkFlagRequired("current")
	_ = cmd.MarkFlagRequired("baseline")

	return cmd
}
