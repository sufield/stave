package export

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	apposcal "github.com/sufield/stave/internal/app/oscal"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/platform/fsutil"
)

func newOSCALCmd() *cobra.Command {
	var assessmentPath, outputPath string

	cmd := &cobra.Command{
		Use:   "oscal",
		Short: "Export findings as OSCAL 1.1.2 Assessment Results JSON",
		Long: `Convert assessment findings to an OSCAL Assessment Results document
for FedRAMP, FISMA, and DoD automated toolchain ingestion.

UUIDs are deterministic (derived from control_id + asset_id).

Exit Codes:
  0   Export complete
  2   Invalid input`,
		Example:       `  stave export oscal --assessment findings.json --out oscal-results.json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runOSCAL(cmd.OutOrStdout(), assessmentPath, outputPath)
		},
	}

	cmd.Flags().StringVar(&assessmentPath, "assessment", "", "stave apply JSON output (required)")
	cmd.Flags().StringVar(&outputPath, "out", "", "write to file")
	_ = cmd.MarkFlagRequired("assessment")

	return cmd
}

func runOSCAL(stdout io.Writer, assessmentPath, outputPath string) error {
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

	result := apposcal.Export(assessment.Findings, time.Now().UTC())

	w := stdout
	if outputPath != "" {
		f, fErr := os.Create(outputPath) //nolint:gosec // user-specified output
		if fErr != nil {
			return fmt.Errorf("create output: %w", fErr)
		}
		defer f.Close()
		w = f
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}
