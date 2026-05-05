package export

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	appocsf "github.com/sufield/stave/internal/app/ocsf"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/platform/fsutil"
)

func newOCSFCmd() *cobra.Command {
	var assessmentPath, outputPath string

	cmd := &cobra.Command{
		Use:   "ocsf",
		Short: "Export findings as OCSF 1.1 Compliance Finding events",
		Long: `Convert assessment findings to OCSF 1.1 events (class_uid: 2003)
for SIEM ingestion (Splunk, Sentinel, Elastic, Panther).

Output is NDJSON — one event per line.

Exit Codes:
  0   Export complete
  2   Invalid input`,
		Example:       `  stave export ocsf --assessment findings.json --output ocsf-events.json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runOCSF(cmd.OutOrStdout(), assessmentPath, outputPath)
		},
	}

	cmd.Flags().StringVar(&assessmentPath, "assessment", "", "stave apply JSON output (required)")
	cmd.Flags().StringVar(&outputPath, "output", "", "write NDJSON to file")
	cliflags.MustMarkRequired(cmd, "assessment")

	return cmd
}

func runOCSF(stdout io.Writer, assessmentPath, outputPath string) error {
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

	events := appocsf.Export(assessment.Findings)

	return cmdutil.WriteTo(stdout, outputPath, func(w io.Writer) error {
		// NDJSON: one event per line.
		enc := json.NewEncoder(w)
		for i := range events {
			if encErr := enc.Encode(&events[i]); encErr != nil {
				return fmt.Errorf("encode event: %w", encErr)
			}
		}
		return nil
	})
}
