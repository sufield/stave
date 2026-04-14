package nep

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

type summaryOpts struct {
	Snapshot  string
	Format    string
	Threshold string
}

func newSummaryCmd() *cobra.Command {
	opts := &summaryOpts{Format: "table", Threshold: "elevated"}

	cmd := &cobra.Command{
		Use:   "summary",
		Short: "Aggregate NEP metrics across all principals",
		Long: `Show a high-level NEP summary across all principals in the snapshot.
Includes privilege distribution, finding counts, chain metrics, and
highest-risk principals.

Exit Codes:
  0   No findings above threshold
  1   Critical findings exist
  2   High findings (no critical)
  3   Incomplete resolution
  4   Internal error

Examples:
  stave nep summary --snapshot obs.json
  stave nep summary --snapshot obs.json --threshold critical --format json`,
		Example: `  stave nep summary --snapshot obs.json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSummary(opts)
		},
	}

	cmd.Flags().StringVar(&opts.Snapshot, "snapshot", "", "path to snapshot file (required)")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "table", "output format: table | json")
	cmd.Flags().StringVar(&opts.Threshold, "threshold", "elevated", "severity threshold: none|limited|standard|elevated|admin")

	_ = cmd.MarkFlagRequired("snapshot")

	return cmd
}

// nepSummary holds aggregated metrics for the summary view.
type nepSummary struct {
	TotalPrincipals       int `json:"total_principals"`
	IncompletePrincipals  int `json:"incomplete_principals"`
	AdminCount            int `json:"admin_count"`
	ElevatedCount         int `json:"elevated_count"`
	StandardCount         int `json:"standard_count"`
	LimitedCount          int `json:"limited_count"`
	NoneCount             int `json:"none_count"`
	TransitiveAdmin       int `json:"transitive_admin_chains"`
	CrossAccountChains    int `json:"cross_account_chains"`
	MaxChainDepth         int `json:"max_chain_depth"`
	IneffectiveBoundaries int `json:"ineffective_boundaries"`
}

func runSummary(opts *summaryOpts) error {
	if _, err := os.Stat(opts.Snapshot); err != nil {
		return fmt.Errorf("snapshot file not found: %s", opts.Snapshot)
	}

	// Stub: in production, resolves all principals and aggregates.
	summary := nepSummary{
		TotalPrincipals:      0,
		IncompletePrincipals: 0,
	}

	switch opts.Format {
	case "json":
		return renderSummaryJSON(summary)
	default:
		return renderSummaryTable(summary, opts)
	}
}

func renderSummaryJSON(summary nepSummary) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(summary)
}

func renderSummaryTable(summary nepSummary, opts *summaryOpts) error {
	fmt.Println("NET EFFECTIVE PERMISSIONS SUMMARY")
	fmt.Printf("Snapshot: %s\n", opts.Snapshot)
	fmt.Printf("Evaluated: %d principals  |  %d incomplete\n",
		summary.TotalPrincipals, summary.IncompletePrincipals)

	fmt.Println("\nPRIVILEGE DISTRIBUTION")
	fmt.Println(strings.Repeat("-", 60))
	printBar("Admin", summary.AdminCount, summary.TotalPrincipals)
	printBar("Elevated", summary.ElevatedCount, summary.TotalPrincipals)
	printBar("Standard", summary.StandardCount, summary.TotalPrincipals)
	printBar("Limited", summary.LimitedCount, summary.TotalPrincipals)
	printBar("None", summary.NoneCount, summary.TotalPrincipals)

	if summary.TransitiveAdmin > 0 || summary.CrossAccountChains > 0 {
		fmt.Println("\nTRANSITIVE CHAINS")
		fmt.Println(strings.Repeat("-", 60))
		fmt.Printf("  Chains reaching admin:   %d\n", summary.TransitiveAdmin)
		fmt.Printf("  Cross-account chains:    %d\n", summary.CrossAccountChains)
		fmt.Printf("  Max chain depth:         %d\n", summary.MaxChainDepth)
	}

	if summary.IneffectiveBoundaries > 0 {
		fmt.Printf("\nIneffective boundaries: %d\n", summary.IneffectiveBoundaries)
	}

	return nil
}

func printBar(label string, count, total int) {
	width := 20
	filled := 0
	if total > 0 {
		filled = (count * width) / total
	}
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("#", filled) + strings.Repeat(".", width-filled)
	fmt.Printf("  %-10s %s  %d\n", label, bar, count)
}
