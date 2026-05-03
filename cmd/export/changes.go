package export

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/app/exportchanges"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/util/jsonutil"
)

func newChangesCmd() *cobra.Command {
	var assessmentPath, outputPath string
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
  stave export changes --assessment findings.json --min-confidence 0.8 --output changes.json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runChanges(cmd.OutOrStdout(), assessmentPath, outputPath, minConfidence)
		},
	}

	cmd.Flags().StringVar(&assessmentPath, "assessment", "", "stave apply JSON output (required)")
	cmd.Flags().StringVar(&outputPath, "output", "", "write JSON to file")
	cmd.Flags().Float64Var(&minConfidence, "min-confidence", 0, "minimum remediation confidence (0.0-1.0)")
	_ = cmd.MarkFlagRequired("assessment")

	return cmd
}

func runChanges(stdout io.Writer, assessmentPath, outputPath string, minConfidence float64) error {
	data, err := fsutil.ReadFileLimited(assessmentPath)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("read assessment: %w", err)}
	}
	var assessment struct {
		Findings []remediation.Finding `json:"findings"`
	}
	if unmarshalErr := json.Unmarshal(data, &assessment); unmarshalErr != nil {
		return &ui.UserError{Err: fmt.Errorf("parse assessment: %w", unmarshalErr)}
	}

	report := exportchanges.Export(exportchanges.Input{
		Findings:      assessment.Findings,
		MinConfidence: minConfidence,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
	})

	return cmdutil.WriteTo(stdout, outputPath, func(w io.Writer) error {
		return jsonutil.WriteIndented(w, report)
	})
}
