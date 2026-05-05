package export

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	apposcal "github.com/sufield/stave/internal/app/oscal"
	"github.com/sufield/stave/internal/app/oscalpoam"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/platform/fsutil"
)

func newOSCALCmd() *cobra.Command {
	var assessmentPath, outputPath, docType, systemUUID string

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
		Example: `  stave export oscal --assessment findings.json --out oscal-results.json
  stave export oscal --assessment findings.json --type poam --system-uuid abc-123`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runOSCAL(cmd.OutOrStdout(), assessmentPath, outputPath, docType, systemUUID)
		},
	}

	cmd.Flags().StringVar(&assessmentPath, "assessment", "", "stave apply JSON output (required)")
	cmd.Flags().StringVar(&outputPath, "out", "", "write to file")
	cmd.Flags().StringVar(&docType, "type", "assessment-results", "OSCAL document type: assessment-results, poam, ssp")
	cmd.Flags().StringVar(&systemUUID, "system-uuid", "", "system UUID for POA&M generation")
	cliflags.MustMarkRequired(cmd, "assessment")

	return cmd
}

func runOSCAL(stdout io.Writer, assessmentPath, outputPath, docType, systemUUID string) error {
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

	now := time.Now().UTC()

	var result any
	switch docType {
	case "poam":
		result = oscalpoam.Generate(oscalpoam.Input{
			Findings:   assessment.Findings,
			SystemUUID: systemUUID,
			Now:        now,
		})
	case "ssp":
		return &ui.UserError{Err: errors.New("OSCAL SSP export is not yet implemented")}
	default:
		result = apposcal.Export(assessment.Findings, now)
	}

	return cmdutil.WriteTo(stdout, outputPath, func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	})
}
