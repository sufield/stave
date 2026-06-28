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

func newOSCALCmd() *cobra.Command {
	var assessmentPath, docType, systemUUID string

	cmd := &cobra.Command{
		Use:   "oscal",
		Short: "Export findings as OSCAL 1.1.2 Assessment Results JSON",
		Long: `Convert assessment findings to an OSCAL Assessment Results document
for FedRAMP, FISMA, and DoD automated toolchain ingestion.

UUIDs are deterministic (derived from control_id + asset_id).

Document types:
  assessment-results   Standard assessment results (default)
  poam                 Plan of Action and Milestones
  ssp                  System Security Plan (stub)

Exit Codes:
  0   Export complete
  2   Invalid input`,
		Example: `  stave export oscal --assessment findings.json
  stave export oscal --assessment findings.json --type poam --system-uuid abc-123`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runOSCAL(cmd.OutOrStdout(), assessmentPath, docType, systemUUID)
		},
	}

	cmd.Flags().StringVar(&assessmentPath, "assessment", "", "stave apply JSON output (required)")
	cmd.Flags().StringVar(&docType, "type", "assessment-results", "OSCAL document type: assessment-results, poam, ssp")
	cmd.Flags().StringVar(&systemUUID, "system-uuid", "", "system UUID for POA&M generation")
	cliflags.MustMarkRequired(cmd, "assessment")

	return cmd
}

func runOSCAL(stdout io.Writer, assessmentPath, docType, systemUUID string) error {
	data, err := fsutil.ReadFileLimited(assessmentPath)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("read assessment: %w", err)}
	}
	out, err := stave.ExportOSCAL(data, docType, systemUUID, time.Now().UTC())
	if err != nil {
		if errors.Is(err, stave.ErrInvalidInput) {
			return &ui.UserError{Err: err}
		}
		return err //nolint:wrapcheck // facade already wrapped; preserve exit code.
	}
	if _, err := stdout.Write(out); err != nil {
		return fmt.Errorf("write OSCAL export: %w", err)
	}
	return nil
}
