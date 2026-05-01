package formatter

import (
	"fmt"
	"io"
	"strings"

	apprank "github.com/sufield/stave/internal/app/rank"
)

// TextIdentityRanking renders an identity-centric blast radius
// ranking — one section per identity, listing reachable resources
// with findings and recommended remediation actions.
type TextIdentityRanking struct{}

var _ IdentityRankingFormatter = (*TextIdentityRanking)(nil)

// Render writes the identity ranking to w. Empty rankings emit a
// single explanatory line so consumers piping output into grep see
// the no-data signal rather than a silent empty.
func (TextIdentityRanking) Render(w io.Writer, ranking apprank.IdentityRanking) error {
	if len(ranking.Entries) == 0 {
		_, err := fmt.Fprintln(w, "No identity risk entries found.")
		return err
	}

	fmt.Fprintf(w, "IDENTITY BLAST RADIUS RANKING\n")
	fmt.Fprintf(w, "Identities evaluated: %d  |  Total risk score: %.0f\n",
		ranking.IdentitiesEvaluated, ranking.TotalPortfolioRisk)
	fmt.Fprintln(w, strings.Repeat("=", 90))

	for idx := range ranking.Entries {
		e := &ranking.Entries[idx]

		privilegeLabel := strings.ToUpper(e.PrivilegeLevel)
		if privilegeLabel == "" {
			privilegeLabel = "STANDARD"
		}

		directLabel := "—"
		if len(e.DirectFindingIDs) > 0 {
			directLabel = fmt.Sprintf("%d findings (%s)", len(e.DirectFindingIDs), strings.ToUpper(e.DirectSeverity))
		}

		fmt.Fprintf(w, "\n[#%d]  %s\n", e.Rank, e.IdentityARN)
		fmt.Fprintf(w, "      Type: %s  |  Privilege: %s  |  Reaches: %d resources  |  Risk↓ %.1f%%\n",
			e.IdentityType, privilegeLabel, e.ReachableCount, e.RiskReductionPercent)
		fmt.Fprintf(w, "      Direct: %s\n", directLabel)

		if len(e.ReachableResources) > 0 {
			fmt.Fprintf(w, "      Reachable resources with findings:\n")
			limit := min(len(e.ReachableResources), 10)
			for ri := range limit {
				rr := &e.ReachableResources[ri]
				if len(rr.FindingIDs) == 0 {
					continue
				}
				sevLabel := strings.ToUpper(rr.MaxSeverity)
				if sevLabel == "" {
					sevLabel = "?"
				}
				fmt.Fprintf(w, "        %-50s [%s] via %s\n",
					rr.ResourceARN, sevLabel, rr.AccessPath)
			}
			if len(e.ReachableResources) > 10 {
				fmt.Fprintf(w, "        ... (%d more resources)\n", len(e.ReachableResources)-10)
			}
		}

		if len(e.RemediationActions) > 0 {
			fmt.Fprintf(w, "      Recommended actions:\n")
			for i, act := range e.RemediationActions {
				action := act
				if len(action) > 76 {
					action = action[:73] + "..."
				}
				fmt.Fprintf(w, "        %d. %s\n", i+1, action)
			}
		}
	}
	return nil
}
