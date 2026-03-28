package cidiff

import (
	"io"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/pkg/alpha/domain/ports"
)

// NewCmd constructs the diff command.
func NewCmd() *cobra.Command {
	cfg := Config{
		FailOnNew: true,
	}

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
			return newRunner(cmd).Run(cmd.Context(), cfg)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVar(&cfg.CurrentPath, "current", "", "Path to current evaluation JSON (required)")
	cmd.Flags().StringVar(&cfg.BaselinePath, "baseline", "", "Path to baseline evaluation JSON (required)")
	cmd.Flags().BoolVar(&cfg.FailOnNew, "fail-on-new", cfg.FailOnNew, "Return exit code 3 when new findings are detected")
	_ = cmd.MarkFlagRequired("current")
	_ = cmd.MarkFlagRequired("baseline")

	return cmd
}

func newRunner(cmd *cobra.Command) *Runner {
	gf := cliflags.GetGlobalFlags(cmd)
	stdout := cmd.OutOrStdout()
	if !gf.TextOutputEnabled() {
		stdout = io.Discard
	}
	return NewRunner(
		ports.RealClock{},
		gf.GetSanitizer(),
		stdout,
	)
}
