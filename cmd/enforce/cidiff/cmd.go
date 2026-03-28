package cidiff

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/domain"
	"github.com/sufield/stave/internal/core/usecases"
	"github.com/sufield/stave/internal/metadata"
	formatter "github.com/sufield/stave/internal/ui"
)

// Deps groups the infrastructure implementations for the ci diff command.
type Deps struct {
	UseCaseDeps usecases.CIDiffDeps
}

// NewCmd constructs the diff command.
func NewCmd(deps Deps) *cobra.Command {
	var (
		currentPath  string
		baselinePath string
		failOnNew    = true
	)

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
			req := domain.CIDiffRequest{
				CurrentPath:  currentPath,
				BaselinePath: baselinePath,
				FailOnNew:    failOnNew,
			}

			resp, err := usecases.CIDiff(cmd.Context(), req, deps.UseCaseDeps)
			if err != nil {
				return err
			}

			if renderErr := formatter.RenderJSON(cmd.OutOrStdout(), resp); renderErr != nil {
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

	cmd.Flags().StringVar(&currentPath, "current", "", "Path to current evaluation JSON (required)")
	cmd.Flags().StringVar(&baselinePath, "baseline", "", "Path to baseline evaluation JSON (required)")
	cmd.Flags().BoolVar(&failOnNew, "fail-on-new", failOnNew, "Return exit code 3 when new findings are detected")
	_ = cmd.MarkFlagRequired("current")
	_ = cmd.MarkFlagRequired("baseline")

	return cmd
}
