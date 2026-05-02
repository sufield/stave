package consolidate

import (
	"fmt"
	"io"
	"strings"
)

// WriteTextReport renders a consolidated report in human-readable
// table form. focusAccount, when non-empty, restricts the per-account
// rows to that account ID; the org-level summary block always renders.
//
// The format is intentionally fixed-width for terminal readability;
// JSON consumers should marshal the report directly.
func WriteTextReport(w io.Writer, r *ConsolidatedReport, focusAccount string) {
	fmt.Fprintf(w, "ORGANIZATION SECURITY POSTURE\n")
	if r.OrgName != "" {
		fmt.Fprintf(w, "Organization: %s\n", r.OrgName)
	}
	fmt.Fprintf(w, "Accounts: %d  |  Assessed: %s\n\n",
		r.AccountCount, r.GeneratedAt.Format("2006-01-02 15:04 UTC"))

	fmt.Fprintf(w, "ACCOUNT RISK RANKING\n")
	fmt.Fprintf(w, "%s\n", strings.Repeat("─", 85))
	fmt.Fprintf(w, "%-4s  %-24s %-12s %4s %4s %5s %4s %8s\n",
		"Rank", "Account", "Environment", "Crit", "High", "Chain", "SLA", "Score")
	fmt.Fprintf(w, "%s\n", strings.Repeat("─", 85))

	for i := range r.Accounts {
		a := &r.Accounts[i]
		if focusAccount != "" && a.AccountID.String() != focusAccount {
			continue
		}
		name := a.AccountName
		if len(name) > 24 {
			name = name[:21] + "..."
		}
		env := a.Environment
		if len(env) > 12 {
			env = env[:9] + "..."
		}
		fmt.Fprintf(w, "%4d  %-24s %-12s %4d %4d %5d %4d %8.0f\n",
			a.OrgRiskRank, name, env,
			a.CriticalCount, a.HighCount, a.ActiveChains, a.SLABreached, a.RiskScore)
	}

	fmt.Fprintf(w, "\nORG POSTURE SUMMARY\n")
	fmt.Fprintf(w, "%s\n", strings.Repeat("─", 85))
	p := &r.OrgPosture
	fmt.Fprintf(w, "Total findings: %d  Critical: %d  Chains: %d  SLA breached: %d\n",
		p.TotalFindings, p.CriticalFindings, p.ChainFindings, p.SLABreached)
	if p.HighestRiskAccount != "" {
		fmt.Fprintf(w, "Highest risk account: %s\n", p.HighestRiskAccount)
	}
	if p.CrossAccountIdentities > 0 {
		fmt.Fprintf(w, "Cross-account identities: %d\n", p.CrossAccountIdentities)
	}

	if len(r.CrossAccount) > 0 {
		fmt.Fprintf(w, "\nCROSS-ACCOUNT FINDINGS (%d)\n", len(r.CrossAccount))
		fmt.Fprintf(w, "%s\n", strings.Repeat("─", 85))
		for i := range r.CrossAccount {
			cf := &r.CrossAccount[i]
			sev := strings.ToUpper(cf.Severity)
			fmt.Fprintf(w, "[%s] %s\n", sev, cf.Type)
			fmt.Fprintf(w, "  %s/%s\n    → %s/%s\n",
				cf.SourceAccountID, cf.SourcePrincipal,
				cf.TargetAccountID, cf.TargetResource)
			fmt.Fprintf(w, "  %s\n\n", cf.Description)
		}
	}
}
