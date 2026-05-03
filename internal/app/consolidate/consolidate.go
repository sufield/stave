package consolidate

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/sufield/stave/internal/core/access"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
	corereport "github.com/sufield/stave/internal/core/report"
	"github.com/sufield/stave/internal/util/props"

	appeval "github.com/sufield/stave/internal/app/eval"
)

// Input holds everything needed for consolidation.
type Input struct {
	Accounts     []AccountInput
	Controls     []policy.ControlDefinition
	ChainDefs    []policy.ChainDefinition
	SLAConfig    *evaluation.SLAConfig
	CELEvaluator policy.PredicateEval
	OrgName      string
	Now          time.Time

	// AccountIDFromARN extracts the account-ID component from a
	// principal or resource identifier. Provider-specific (an AWS
	// implementation parses ARNs); injected so this package stays
	// vendor-neutral. Optional — when nil, cross-account analysis
	// is skipped and a warning is appended.
	AccountIDFromARN func(string) string

	// BuildResourceAccessIndex builds a per-snapshot index of
	// resource-based policy grants. Provider-specific. Optional —
	// when nil, cross-account analysis is skipped and a warning is
	// appended.
	BuildResourceAccessIndex func(*asset.Snapshot) *access.ResourceAccessIndex
}

// AccountInput represents a single account to evaluate.
type AccountInput struct {
	AccountID    AccountID
	AccountName  string
	Environment  string
	BusinessUnit string
	Snapshots    []asset.Snapshot
}

// ToSummaryHeader returns an AccountSummary pre-populated with the
// account-owned fields (ID / name / environment / business unit /
// SnapshotAt). Severity counts, SLA breaches, ActiveChains and
// RiskScore are left zero — the caller fills them in after the
// per-finding pass. Centralising the field copy here keeps the
// caller from reaching into AccountInput's fields one by one when a
// future addition (e.g. a region label) lands on the type.
//
// SnapshotAt is taken from the most recent snapshot's CapturedAt.
// Returns the zero summary when Snapshots is empty so callers can
// branch on a missing timestamp without panicking on the index.
func (a *AccountInput) ToSummaryHeader() AccountSummary {
	if a == nil {
		return AccountSummary{}
	}
	s := AccountSummary{
		AccountID:    a.AccountID,
		AccountName:  a.AccountName,
		Environment:  a.Environment,
		BusinessUnit: a.BusinessUnit,
	}
	if len(a.Snapshots) > 0 {
		s.SnapshotAt = a.Snapshots[len(a.Snapshots)-1].CapturedAt
	}
	return s
}

// Run performs multi-account consolidation: per-account assessment +
// org-level synthesis + cross-account analysis.
func Run(ctx context.Context, input Input) (*ConsolidatedReport, []string, error) {
	if len(input.Accounts) == 0 {
		return nil, nil, errors.New("no accounts to consolidate")
	}

	var warnings []string
	now := input.Now
	if now.IsZero() {
		return nil, nil, errors.New("now is required (use ports.Clock or --now)")
	}

	report := &ConsolidatedReport{
		GeneratedAt:  now,
		OrgName:      input.OrgName,
		AccountCount: len(input.Accounts),
	}

	// Track snapshot times for staleness detection.
	var earliest, latest time.Time
	var totalRisk float64
	var productionRisk, nonProductionRisk float64

	// Per-account assessment.
	for i := range input.Accounts {
		acct := &input.Accounts[i]
		summary, acctRisk, err := assessAccount(ctx, acct, input.Controls, input.ChainDefs, input.SLAConfig, input.CELEvaluator)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("account %s: assessment failed: %v", acct.AccountID, err))
			continue
		}

		report.Accounts = append(report.Accounts, summary)
		totalRisk += acctRisk

		if acct.Environment == "production" {
			productionRisk += acctRisk
		} else {
			nonProductionRisk += acctRisk
		}

		if earliest.IsZero() || summary.SnapshotAt.Before(earliest) {
			earliest = summary.SnapshotAt
		}
		if latest.IsZero() || summary.SnapshotAt.After(latest) {
			latest = summary.SnapshotAt
		}

		report.OrgPosture.TotalFindings += summary.TotalFindings
		report.OrgPosture.CriticalFindings += summary.CriticalCount
		report.OrgPosture.ChainFindings += summary.ActiveChains
		report.OrgPosture.SLABreached += summary.SLABreached
	}

	// Snapshot period and staleness check.
	report.SnapshotPeriod = SnapshotPeriod{
		Earliest:    earliest,
		Latest:      latest,
		MaxGapHours: latest.Sub(earliest).Hours(),
	}
	if report.SnapshotPeriod.MaxGapHours > 24 {
		warnings = append(warnings, fmt.Sprintf(
			"snapshots span %.0f hours — cross-account analysis may reflect different points in time",
			report.SnapshotPeriod.MaxGapHours))
	}

	// Rank accounts by risk.
	sort.Slice(report.Accounts, func(i, j int) bool {
		return report.Accounts[i].RiskScore > report.Accounts[j].RiskScore
	})
	for i := range report.Accounts {
		report.Accounts[i].OrgRiskRank = i + 1
	}

	if len(report.Accounts) > 0 {
		report.OrgPosture.HighestRiskAccount = report.Accounts[0].AccountID.String()
	}

	if totalRisk > 0 {
		report.OrgPosture.ProductionRisk = (productionRisk / totalRisk) * 100
		report.OrgPosture.NonProductionRisk = (nonProductionRisk / totalRisk) * 100
	}

	// Cross-account analysis. Skipped when either provider helper
	// is missing — see Input.AccountIDFromARN /
	// Input.BuildResourceAccessIndex docs. detectCrossAccountFindings
	// also nil-guards the call internally; the call-site check here
	// avoids the function-call overhead in the common test path.
	if input.AccountIDFromARN != nil && input.BuildResourceAccessIndex != nil {
		crossFindings, crossIdentities := detectCrossAccountFindings(
			input.Accounts,
			input.AccountIDFromARN,
			input.BuildResourceAccessIndex,
		)
		report.CrossAccount = crossFindings
		report.OrgPosture.CrossAccountIdentities = crossIdentities
	}

	return report, warnings, nil
}

func assessAccount(
	ctx context.Context,
	acct *AccountInput,
	controls []policy.ControlDefinition,
	chainDefs []policy.ChainDefinition,
	slaCfg *evaluation.SLAConfig,
	celEval policy.PredicateEval,
) (AccountSummary, float64, error) {
	if len(acct.Snapshots) == 0 {
		return AccountSummary{}, 0, errors.New("no snapshots")
	}

	result, err := appeval.EvaluateLoaded(ctx, appeval.EvaluationRequest{
		Controls:     controls,
		Snapshots:    acct.Snapshots,
		CELEvaluator: celEval,
	})
	if err != nil {
		return AccountSummary{}, 0, err
	}

	// Enrich with chains.
	appeval.EnrichReport(&result, controls, chainDefs)

	// Annotate SLA.
	if slaCfg != nil {
		ctlLookup := make(map[kernel.ControlID]*policy.ControlDefinition, len(controls))
		for i := range controls {
			ctlLookup[controls[i].ID] = &controls[i]
		}
		for i := range result.Findings {
			ctl := ctlLookup[result.Findings[i].ControlID]
			evaluation.AnnotateFindingSLA(&result.Findings[i], ctl, slaCfg)
		}
	}

	// Build summary. Account-owned header fields come from the
	// account itself; computed fields (ActiveChains, severity counts,
	// risk score) are filled in below.
	summary := acct.ToSummaryHeader()
	summary.ActiveChains = len(result.ChainFindings)

	var counts corereport.SeverityCounts
	var riskScore float64
	for i := range result.Findings {
		f := &result.Findings[i]
		summary.TotalFindings++
		counts.Add(f.ControlSeverity)
		if f.IsAnyBreach() {
			summary.SLABreached++
		}
		base := float64(f.ControlSeverity.Weight())
		dur := risk.DurationFactor(f.Evidence.UnsafeDurationHours)
		riskScore += base * dur
	}
	summary.CriticalCount = counts.Critical
	summary.HighCount = counts.High
	summary.MediumCount = counts.Medium
	summary.LowCount = counts.Low
	summary.RiskScore = math.Round(riskScore)

	return summary, riskScore, nil
}

// detectCrossAccountFindings checks for cross-account resource policy
// grants and execution role links between accounts. accountIDFromARN
// and buildIndex are vendor-specific helpers injected via Input;
// either being nil disables the analysis (the helper is also called
// from a guard in Run, but defending here makes the function safe
// for direct callers too).
func detectCrossAccountFindings(
	accounts []AccountInput,
	accountIDFromARN func(string) string,
	buildIndex func(*asset.Snapshot) *access.ResourceAccessIndex,
) ([]CrossAccountFinding, int) {
	if accountIDFromARN == nil || buildIndex == nil {
		return nil, 0
	}
	// Build a map of all assets by account.
	type assetInfo struct {
		accountID string
		asset     *asset.Asset
	}
	allAssets := make(map[string]assetInfo)
	for i := range accounts {
		acct := &accounts[i]
		for si := range acct.Snapshots {
			for ai := range acct.Snapshots[si].Assets {
				a := &acct.Snapshots[si].Assets[ai]
				allAssets[string(a.ID)] = assetInfo{
					accountID: acct.AccountID.String(),
					asset:     a,
				}
			}
		}
	}

	var findings []CrossAccountFinding
	crossAccountPrincipals := make(map[string]bool)

	// Check resource policies for cross-account grants.
	for i := range accounts {
		acct := &accounts[i]
		for si := range acct.Snapshots {
			snap := &acct.Snapshots[si]
			idx := buildIndex(snap)
			if idx == nil {
				continue
			}
			for ai := range snap.Assets {
				resourceARN := string(snap.Assets[ai].ID)
				resourceAcct := accountIDFromARN(resourceARN)
				entries := idx.EntriesFor(resourceARN)
				for _, entry := range entries {
					if entry.IsPublic {
						continue
					}
					principalAcct := accountIDFromARN(entry.PrincipalARN)
					if principalAcct == "" || principalAcct == resourceAcct {
						continue
					}
					// Cross-account grant found.
					if _, inOrg := allAssets[entry.PrincipalARN]; !inOrg {
						continue // principal not in any org snapshot
					}
					crossAccountPrincipals[entry.PrincipalARN] = true
					findings = append(findings, CrossAccountFinding{
						FindingID:       fmt.Sprintf("xacct:%s:%s", entry.PrincipalARN, resourceARN),
						Type:            "cross_account_resource_grant",
						SourceAccountID: principalAcct,
						TargetAccountID: resourceAcct,
						SourcePrincipal: entry.PrincipalARN,
						TargetResource:  resourceARN,
						Severity:        "high",
						Description: fmt.Sprintf(
							"Cross-account principal %s has resource-policy access to %s",
							entry.PrincipalARN, resourceARN),
					})
				}
			}
		}
	}

	// Check execution role links across accounts.
	for _, info := range allAssets {
		a := info.asset
		roleARN := props.GetString(a.Properties, []string{"compute", "execution_role", "role_arn"})
		if roleARN == "" {
			continue
		}
		roleAcct := accountIDFromARN(roleARN)
		assetAcct := accountIDFromARN(string(a.ID))
		if roleAcct == "" || roleAcct == assetAcct {
			continue
		}
		if _, inOrg := allAssets[roleARN]; !inOrg {
			continue
		}
		crossAccountPrincipals[roleARN] = true
		findings = append(findings, CrossAccountFinding{
			FindingID:       fmt.Sprintf("xacct:%s:%s", roleARN, a.ID),
			Type:            "cross_account_role_chain",
			SourceAccountID: roleAcct,
			TargetAccountID: assetAcct,
			SourcePrincipal: roleARN,
			TargetResource:  string(a.ID),
			Severity:        "critical",
			Description: fmt.Sprintf(
				"Cross-account role %s executes function %s in account %s",
				roleARN, a.ID, assetAcct),
		})
	}

	return findings, len(crossAccountPrincipals)
}
