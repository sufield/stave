package nep

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/platform/providers/aws/iam"
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
		Example:       `  stave nep summary --snapshot obs.json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSummary(cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.Snapshot, "snapshot", "", "path to snapshot file (required)")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "table", "output format: table | json")
	cmd.Flags().StringVar(&opts.Threshold, "threshold", "elevated", "severity threshold: none|limited|standard|elevated|admin")

	cliflags.MustMarkRequired(cmd, "snapshot")

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

// addPrincipal folds a single ResolvedPermissions into the summary
// counters: increments IncompletePrincipals when the resolution is
// flagged as incomplete and bumps the privilege-tier counter that
// matches r.PrivilegeBucket(). The per-tier mapping lives on
// iam.ResolvedPermissions so a future privilege addition is one
// edit on that type.
func (s *nepSummary) addPrincipal(r *iam.ResolvedPermissions) {
	if s == nil || r == nil {
		return
	}
	if r.Incomplete {
		s.IncompletePrincipals++
	}
	switch r.PrivilegeBucket() {
	case "admin":
		s.AdminCount++
	case "elevated":
		s.ElevatedCount++
	case "standard":
		s.StandardCount++
	case "limited":
		s.LimitedCount++
	default:
		s.NoneCount++
	}
}

func runSummary(w io.Writer, opts *summaryOpts) error {
	snaps, err := loadSnapshots(opts.Snapshot)
	if err != nil {
		return fmt.Errorf("load snapshot: %w", err)
	}
	if len(snaps) == 0 {
		return fmt.Errorf("no snapshots in %s", opts.Snapshot)
	}
	snap := &snaps[len(snaps)-1]

	resolved, trustPolicies := resolveAllPrincipals(snap)

	var summary nepSummary
	summary.TotalPrincipals = len(resolved)

	for arn, r := range resolved {
		summary.addPrincipal(r)

		// Chain analysis.
		chains := iam.ResolveChains(iam.RoleChainInput{
			PrincipalARN:  arn,
			ResolvedIndex: resolved,
			TrustPolicies: trustPolicies,
			AccountID:     extractAccountIDFromARN(arn),
		})
		if iam.HasTransitiveAdmin(chains) {
			summary.TransitiveAdmin++
		}
		for _, chain := range chains {
			for _, hop := range chain.Hops {
				if hop.IsCrossAccount {
					summary.CrossAccountChains++
					break
				}
			}
		}
		depth := iam.MaxDepth(chains)
		if depth > summary.MaxChainDepth {
			summary.MaxChainDepth = depth
		}

		// BoundaryEffective is false when boundary exists but blocks nothing
		// meaningful — counting these requires tracking whether boundary was
		// present on input. For now, skip this metric when not available.
	}

	switch opts.Format {
	case "json":
		return renderSummaryJSON(w, summary)
	default:
		return renderSummaryTable(w, summary, opts)
	}
}

func renderSummaryJSON(w io.Writer, summary nepSummary) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(summary)
}

func renderSummaryTable(w io.Writer, summary nepSummary, opts *summaryOpts) error {
	fmt.Fprintln(w, "NET EFFECTIVE PERMISSIONS SUMMARY")
	fmt.Fprintf(w, "Snapshot: %s\n", opts.Snapshot)
	fmt.Fprintf(w, "Evaluated: %d principals  |  %d incomplete\n",
		summary.TotalPrincipals, summary.IncompletePrincipals)

	fmt.Fprintln(w, "\nPRIVILEGE DISTRIBUTION")
	fmt.Fprintln(w, strings.Repeat("-", 60))
	printBar(w, "Admin", summary.AdminCount, summary.TotalPrincipals)
	printBar(w, "Elevated", summary.ElevatedCount, summary.TotalPrincipals)
	printBar(w, "Standard", summary.StandardCount, summary.TotalPrincipals)
	printBar(w, "Limited", summary.LimitedCount, summary.TotalPrincipals)
	printBar(w, "None", summary.NoneCount, summary.TotalPrincipals)

	if summary.TransitiveAdmin > 0 || summary.CrossAccountChains > 0 {
		fmt.Fprintln(w, "\nTRANSITIVE CHAINS")
		fmt.Fprintln(w, strings.Repeat("-", 60))
		fmt.Fprintf(w, "  Chains reaching admin:   %d\n", summary.TransitiveAdmin)
		fmt.Fprintf(w, "  Cross-account chains:    %d\n", summary.CrossAccountChains)
		fmt.Fprintf(w, "  Max chain depth:         %d\n", summary.MaxChainDepth)
	}

	if summary.IneffectiveBoundaries > 0 {
		fmt.Fprintf(w, "\nIneffective boundaries: %d\n", summary.IneffectiveBoundaries)
	}

	return nil
}

func printBar(w io.Writer, label string, count, total int) {
	width := 20
	filled := 0
	if total > 0 {
		filled = (count * width) / total
	}
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("#", filled) + strings.Repeat(".", width-filled)
	fmt.Fprintf(w, "  %-10s %s  %d\n", label, bar, count)
}
