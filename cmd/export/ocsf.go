package export

import (
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/stave"
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
	out, err := stave.ExportOCSF(data)
	if err != nil {
		if errors.Is(err, stave.ErrInvalidInput) {
			return &ui.UserError{Err: err}
		}
		return err //nolint:wrapcheck // facade already wrapped; preserve exit code.
	}
	if err := cmdutil.WriteTo(stdout, outputPath, func(w io.Writer) error {
		_, werr := w.Write(out)
		return werr
	}); err != nil {
		return fmt.Errorf("write OCSF export: %w", err)
	}
	return nil
}
