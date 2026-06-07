package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/app/teams"
	"github.com/sufield/stave/internal/app/ticketexport"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/platform/fsutil"
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
	var assessment struct {
		Findings []remediation.Finding `json:"findings"`
	}
	if unmarshalErr := json.Unmarshal(data, &assessment); unmarshalErr != nil {
		return &ui.UserError{Err: fmt.Errorf("parse assessment: %w", unmarshalErr)}
	}

	tickets := ticketexport.Generate(assessment.Findings)

	// Apply team manifest enrichment.
	if teamManifest != "" {
		manifest, manifestErr := teams.LoadManifest(teamManifest)
		if manifestErr != nil {
			return fmt.Errorf("load team manifest: %w", manifestErr)
		}
		for i := range tickets {
			t := &tickets[i]
			if t.Team == "" {
				owner := manifest.ResolveOwner(nil, t.AssetID, t.ControlID)
				t.Team = owner.TeamName
			}
		}
	}

	// Filter by team if specified.
	if team != "" {
		var filtered []ticketexport.Ticket
		for i := range tickets {
			if tickets[i].Team == team {
				filtered = append(filtered, tickets[i])
			}
		}
		tickets = filtered
	}

	renderer, rerr := NewTicketsRenderer(format)
	if rerr != nil {
		return &ui.UserError{Err: rerr}
	}

	if err := cmdutil.WriteTo(stdout, outputPath, func(w io.Writer) error {
		return renderer.Render(w, tickets)
	}); err != nil {
		return fmt.Errorf("write tickets export: %w", err)
	}
	return nil
}

func writeTicketsCSV(w io.Writer, tickets []ticketexport.Ticket) (err error) {
	cw := csv.NewWriter(w)
	// Propagate any buffered-flush error back to the caller through a
	// named return. The bare `defer cw.Flush()` shape silently
	// dropped a flush failure on the underlying writer (full disk,
	// closed pipe, network sink hangup), producing a "successful"
	// CSV export that ended mid-row.
	defer func() {
		cw.Flush()
		if flushErr := cw.Error(); flushErr != nil && err == nil {
			err = fmt.Errorf("flush tickets CSV: %w", flushErr)
		}
	}()

	if err = cw.Write([]string{
		"ticket_id", "title", "severity", "priority", "status",
		"control_id", "asset_id", "team", "dwell_days", "description",
	}); err != nil {
		return err
	}

	for i := range tickets {
		t := &tickets[i]
		if err = cw.Write([]string{
			t.TicketID,
			t.Title,
			t.Severity,
			t.Priority,
			t.Status,
			t.ControlID,
			t.AssetID,
			t.Team,
			fmt.Sprintf("%.1f", t.DwellDays),
			t.Description,
		}); err != nil {
			return err
		}
	}
	return nil
}
