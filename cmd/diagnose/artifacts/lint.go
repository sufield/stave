//go:build stavedev

package artifacts

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/app/lint"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// NewLintCmd constructs the lint command.
func NewLintCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lint <path>",
		Short: "Lint control files for design quality",
		Long: `Lint checks control design quality rules independent of schema validity.
It is deterministic, offline, and file-based.

Rules:
  - ID namespace format
  - Required metadata (name/description/remediation)
  - Determinism key constraints
  - Stable ordering hints for list-like sections` + metadata.OfflineHelpSuffix,
		Args:          cobra.ExactArgs(1),
		RunE:          runLint,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
}

func runLint(cmd *cobra.Command, args []string) error {
	target := fsutil.CleanUserPath(args[0])

	diags, err := lint.LintDir(target)
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	for _, d := range diags {
		if _, err = fmt.Fprintf(out, "%s:%d:%d  %s  %s\n", d.Path, d.Line, d.Col, d.RuleID, d.Message); err != nil {
			return err
		}
	}

	if lint.ErrorCount(diags) > 0 {
		return ui.ErrValidationFailed
	}
	return nil
}
