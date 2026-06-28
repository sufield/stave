package export

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/stave"
)

func newChangesCmd() *cobra.Command {
	var assessmentPath string
	var minConfidence float64

	cmd := &cobra.Command{
		Use:   "changes",
		Short: "Export remediation property changes from assessment findings",
		Long: `Extract remediation property changes from assessment findings into
a structured format for external tooling (Terraform, CloudFormation, etc.).

Each change includes the control ID, asset ID, property path,
current value, and required value. Stave provides the data;
external tools generate vendor-specific scripts.

Exit Codes:
  0   Export complete
  2   Invalid input`,
		Example: `  stave export changes --assessment findings.json
  stave export changes --assessment findings.json --min-confidence 0.8`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runChanges(cmd.OutOrStdout(), assessmentPath, minConfidence)
		},
	}

	cmd.Flags().StringVar(&assessmentPath, "assessment", "", "stave apply JSON output (required)")
	cmd.Flags().Float64Var(&minConfidence, "min-confidence", 0, "minimum remediation confidence (0.0-1.0)")
	cliflags.MustMarkRequired(cmd, "assessment")

	return cmd
}

func runChanges(stdout io.Writer, assessmentPath string, minConfidence float64) error {
	data, err := fsutil.ReadFileLimited(assessmentPath)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("read assessment: %w", err)}
	}
	out, err := stave.ExportChanges(data, minConfidence, time.Now().UTC())
	if err != nil {
		if errors.Is(err, stave.ErrInvalidInput) {
			return &ui.UserError{Err: err}
		}
		return err //nolint:wrapcheck // facade already wrapped; preserve exit code.
	}
	if _, err := stdout.Write(out); err != nil {
		return fmt.Errorf("write changes export: %w", err)
	}
	return nil
}
