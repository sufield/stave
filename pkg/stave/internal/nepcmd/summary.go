package nepcmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/sufield/stave/internal/platform/providers/aws/iam"
)

// SummaryConfig parameterizes [NepSummary]. Threshold is accepted for flag
// parity but does not affect the output (it never gated in the CLI either).
type SummaryConfig struct {
	Snapshot  string
	Format    string
	Threshold string
}

// NepSummary aggregates net-effective-permission metrics across all
// principals in the snapshot and renders them (table | json). Load/render
// failures stay plain (exit 4).
func NepSummary(cfg SummaryConfig) ([]byte, error) {
	snaps, err := loadSnapshots(cfg.Snapshot)
	if err != nil {
		return nil, fmt.Errorf("load snapshot: %w", err)
	}
	if len(snaps) == 0 {
		return nil, fmt.Errorf("no snapshots in %s", cfg.Snapshot)
	}
	snap := &snaps[len(snaps)-1]

	resolved, trustPolicies := iam.ResolveAllPrincipals(snap)

	var summary nepSummary
	summary.TotalPrincipals = len(resolved)

	for arn, r := range resolved {
		summary.addPrincipal(r)

		chains := iam.ResolveChains(iam.RoleChainInput{
			PrincipalARN:  arn,
			ResolvedIndex: resolved,
			TrustPolicies: trustPolicies,
			AccountID:     iam.ExtractAccountIDFromARN(arn),
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
	}

	var buf bytes.Buffer
	if err := renderSummary(cfg.Format, &buf, summary, cfg); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// renderSummary dispatches to the format-specific summary renderer.
func renderSummary(format string, w io.Writer, summary nepSummary, cfg SummaryConfig) error {
	switch format {
	case "json":
		return renderSummaryJSON(w, summary)
	case "table", "":
		return renderSummaryTable(w, summary, cfg)
	}
	return fmt.Errorf("unsupported format %q (expected: table | json)", format)
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

func renderSummaryJSON(w io.Writer, summary nepSummary) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(summary)
}

func renderSummaryTable(w io.Writer, summary nepSummary, cfg SummaryConfig) error {
	fmt.Fprintln(w, "NET EFFECTIVE PERMISSIONS SUMMARY")
	fmt.Fprintf(w, "Snapshot: %s\n", cfg.Snapshot)
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
