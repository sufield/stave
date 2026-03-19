//go:build stavedev

package cmd

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/pkg/jsonutil"
)

func newSchemasCmd() *cobra.Command {
	var format string

	cmd := &cobra.Command{
		Use:   "schemas",
		Short: "List all contract schemas",
		Long: `Schemas lists every wire-format contract schema that this version of Stave
reads or writes, grouped by category.

Exit Codes:
  0   - Success
  4   - Internal error

Examples:
  # List all schemas
  stave schemas

  # JSON output
  stave schemas --format json

  # Pipe to jq
  stave schemas --format json | jq '.data'` + OfflineHelpSuffix,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmtValue, err := compose.ResolveFormatValue(cmd, format)
			if err != nil {
				return err
			}
			return writeSchemas(cmd.OutOrStdout(), fmtValue)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVar(&format, "format", "text", "Output format (text, json)")

	return cmd
}

type schemaEntry struct {
	Name   string `json:"name"`
	Schema string `json:"schema"`
}

type schemasOutput struct {
	Data          []schemaEntry `json:"data"`
	Diagnostic    []schemaEntry `json:"diagnostic"`
	CommandOutput []schemaEntry `json:"command_output"`
	Artifact      []schemaEntry `json:"artifact"`
}

func writeSchemas(w io.Writer, format ui.OutputFormat) error {
	out := schemasOutput{
		Data: []schemaEntry{
			{"control", kernel.SchemaControl.String()},
			{"observation", kernel.SchemaObservation.String()},
			{"output", kernel.SchemaOutput.String()},
		},
		Diagnostic: []schemaEntry{
			{"diagnose", kernel.SchemaDiagnose.String()},
			{"diff", kernel.SchemaDiff.String()},
		},
		CommandOutput: []schemaEntry{
			{"baseline", kernel.SchemaBaseline.String()},
			{"ci_diff", kernel.SchemaCIDiff.String()},
			{"enforce", kernel.SchemaEnforce.String()},
			{"fix_loop", kernel.SchemaFixLoop.String()},
			{"gate", kernel.SchemaGate.String()},
			{"snapshot_archive", kernel.SchemaSnapshotArchive.String()},
			{"snapshot_plan", kernel.SchemaSnapshotPlan.String()},
			{"snapshot_prune", kernel.SchemaSnapshotPrune.String()},
			{"snapshot_quality", kernel.SchemaSnapshotQuality.String()},
			{"validate", kernel.SchemaValidate.String()},
		},
		Artifact: []schemaEntry{
			{"bug_report", kernel.SchemaBugReport.String()},
			{"control_crosswalk_resolution", kernel.SchemaCrosswalkResolution.String()},
			{"security_audit", kernel.SchemaSecurityAudit.String()},
			{"security_audit_artifacts", kernel.SchemaSecurityAuditArtifacts.String()},
			{"security_audit_run_manifest", kernel.SchemaSecurityAuditRunManifest.String()},
		},
	}

	if format.IsJSON() {
		return jsonutil.WriteIndented(w, out)
	}

	groups := []struct {
		heading string
		entries []schemaEntry
	}{
		{"Data Contracts", out.Data},
		{"Diagnostic Contracts", out.Diagnostic},
		{"Command Output Contracts", out.CommandOutput},
		{"Artifact Contracts", out.Artifact},
	}

	for i, g := range groups {
		if i > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "%s:\n", g.heading)
		tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
		for _, e := range g.entries {
			fmt.Fprintf(tw, "  %s\t%s\n", e.Name, e.Schema)
		}
		if err := tw.Flush(); err != nil {
			return fmt.Errorf("flush tabwriter: %w", err)
		}
	}
	return nil
}
