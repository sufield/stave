package artifacts

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/adapters/observations"
	"github.com/sufield/stave/internal/app/catalogquality"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/metadata"
)

func newControlsQualityCmd(newCtlRepo compose.CtlRepoFactory) *cobra.Command {
	var controlsDir, snapshotPath, format string
	var minCompleteness float64

	cmd := &cobra.Command{
		Use:   "quality",
		Short: "Analyze control catalog metadata completeness and coverage gaps",
		Long: `Evaluate control catalog quality by checking metadata completeness
(severity, remediation action, attack stage, compliance mappings),
identifying blind spots where observed asset types lack controls,
and detecting MITRE ATT&CK stage coverage gaps.

Inputs:
  --controls           Path to control definitions directory
  --snapshot           Path to observation snapshot for blind spot detection
  --format             Output format: table or json (default: table)
  --min-completeness   Minimum overall completeness percentage (exit 1 if below)

Exit Codes:
  0   Quality report generated
  1   Completeness below --min-completeness threshold
  2   Input error
  4   Internal error` + metadata.OfflineHelpSuffix,
		Example: `  stave controls quality --controls controls/s3
  stave controls quality --controls controls/ --snapshot observations/latest.json
  stave controls quality --controls controls/ --min-completeness 80 --format json`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			controls, err := compose.LoadControlsFrom(cmd.Context(), newCtlRepo, controlsDir)
			if err != nil {
				return fmt.Errorf("load controls: %w", err)
			}

			input := catalogquality.Input{
				Controls: controls,
			}

			if snapshotPath != "" {
				snapshots, snapErr := observations.LoadBundle(snapshotPath)
				if snapErr != nil {
					return fmt.Errorf("load snapshot: %w", snapErr)
				}
				assetTypes := make(map[kernel.AssetType]int)
				for i := range snapshots {
					for j := range snapshots[i].Assets {
						assetTypes[snapshots[i].Assets[j].Type]++
					}
				}
				input.AssetTypes = assetTypes
			}

			report := catalogquality.Analyze(input)

			stdout := cmd.OutOrStdout()
			if format == "json" {
				if encErr := writeQualityJSON(stdout, report); encErr != nil {
					return encErr
				}
			} else {
				writeQualityTable(stdout, report)
			}

			if minCompleteness > 0 && report.OverallPct < minCompleteness {
				return fmt.Errorf("overall completeness %.1f%% is below threshold %.1f%%", report.OverallPct, minCompleteness)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&controlsDir, "controls", "i", cliflags.DefaultControlsDir, "Path to control definitions directory")
	cmd.Flags().StringVar(&snapshotPath, "snapshot", "", "Path to observation snapshot for blind spot detection")
	cmd.Flags().StringVarP(&format, "format", "f", "table", "Output format: table or json")
	cmd.Flags().Float64Var(&minCompleteness, "min-completeness", 0, "Minimum overall completeness percentage (exit 1 if below)")

	return cmd
}

func writeQualityJSON(w io.Writer, r catalogquality.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func writeQualityTable(w io.Writer, r catalogquality.Report) {
	fmt.Fprintf(w, "CATALOG QUALITY REPORT\n")
	fmt.Fprintf(w, "Total controls: %d\n", r.TotalControls)
	fmt.Fprintf(w, "Overall completeness: %.1f%%\n", r.OverallPct)
	fmt.Fprintln(w, strings.Repeat("-", 50))

	fmt.Fprintln(w, "\nFIELD COMPLETENESS")
	fmt.Fprintf(w, "  %-25s %8s %8s\n", "Field", "Present", "Missing")
	fmt.Fprintf(w, "  %-25s %8s %8s\n", strings.Repeat("-", 25), strings.Repeat("-", 8), strings.Repeat("-", 8))

	// Sort fields for deterministic output.
	fields := make([]string, 0, len(r.Completeness))
	for f := range r.Completeness {
		fields = append(fields, f)
	}
	sort.Strings(fields)

	for _, f := range fields {
		fs := r.Completeness[f]
		fmt.Fprintf(w, "  %-25s %8d %8d\n", f, fs.Present, fs.Missing)
	}

	if len(r.BlindSpots) > 0 {
		fmt.Fprintln(w, "\nBLIND SPOTS (asset types with no controls)")
		for _, bs := range r.BlindSpots {
			fmt.Fprintf(w, "  %-40s %d assets\n", bs.AssetType, bs.AssetCount)
		}
	}

	if len(r.MITREGaps) > 0 {
		fmt.Fprintln(w, "\nMITRE ATT&CK STAGE GAPS")
		for _, gap := range r.MITREGaps {
			fmt.Fprintf(w, "  - %s\n", gap)
		}
	}
}
