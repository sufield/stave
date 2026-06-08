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

func newTicketsCmd() *cobra.Command {
	var assessmentPath, outputPath, format, teamManifest, team string

	cmd := &cobra.Command{
		Use:   "tickets",
		Short: "Export findings as canonical ticket records",
		Long: `Generate ticket records from assessment findings with stable IDs,
severity-to-priority mapping, and team assignment. Output as JSON
or CSV for import into Jira, Linear, GitHub Issues, or other
ticketing systems.

Each ticket has a deterministic ID derived from control_id + asset_id,
so re-running the export produces stable references.

Exit Codes:
  0   Export complete
  2   Invalid input`,
		Example: `  stave export tickets --assessment findings.json
  stave export tickets --assessment findings.json --format csv --out tickets.csv
  stave export tickets --assessment findings.json --team-manifest stave-teams.yaml --team platform`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runTickets(cmd.OutOrStdout(), assessmentPath, outputPath, format, teamManifest, team)
		},
	}

	cmd.Flags().StringVar(&assessmentPath, "assessment", "", "stave apply JSON output (required)")
	cmd.Flags().StringVarP(&format, "format", "f", "json", "Output format: json or csv")
	cmd.Flags().StringVar(&outputPath, "out", "", "Write output to file instead of stdout")
	cmd.Flags().StringVar(&teamManifest, "team-manifest", "", "Path to stave-teams.yaml for team assignment")
	cmd.Flags().StringVar(&team, "team", "", "Filter tickets to a specific team")
	cliflags.MustMarkRequired(cmd, "assessment")

	return cmd
}

func runTickets(stdout io.Writer, assessmentPath, outputPath, format, teamManifest, team string) error {
	data, err := fsutil.ReadFileLimited(assessmentPath)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("read assessment: %w", err)}
	}
	out, err := stave.ExportTickets(data, teamManifest, team, format)
	if err != nil {
		if errors.Is(err, stave.ErrInvalidInput) {
			return &ui.UserError{Err: err}
		}
		return err //nolint:wrapcheck // facade already wrapped ("load team manifest"); preserve exit code.
	}
	if err := cmdutil.WriteTo(stdout, outputPath, func(w io.Writer) error {
		_, werr := w.Write(out)
		return werr
	}); err != nil {
		return fmt.Errorf("write tickets export: %w", err)
	}
	return nil
}
