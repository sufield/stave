package consolidate

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/iam"
	"github.com/sufield/stave/internal/core/kernel"
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
}

// AccountInput represents a single account to evaluate.
type AccountInput struct {
	AccountID    string
	AccountName  string
	Environment  string
	BusinessUnit string
	Snapshots    []asset.Snapshot
}

// Run performs multi-account consolidation: per-account assessment +
// org-level synthesis + cross-account analysis.
func Run(input Input) (*ConsolidatedReport, []string, error) {
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
		summary, acctRisk, err := assessAccount(acct, input.Controls, input.ChainDefs, input.SLAConfig, input.CELEvaluator)
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
		report.OrgPosture.HighestRiskAccount = report.Accounts[0].AccountID
	}

	if totalRisk > 0 {
		report.OrgPosture.ProductionRisk = (productionRisk / totalRisk) * 100
		report.OrgPosture.NonProductionRisk = (nonProductionRisk / totalRisk) * 100
	}

	// Cross-account analysis.
	crossFindings, crossIdentities := detectCrossAccountFindings(input.Accounts)
	report.CrossAccount = crossFindings
	report.OrgPosture.CrossAccountIdentities = crossIdentities

	return report, warnings, nil
}

func assessAccount(
	acct *AccountInput,
	controls []policy.ControlDefinition,
	chainDefs []policy.ChainDefinition,
	slaCfg *evaluation.SLAConfig,
	celEval policy.PredicateEval,
) (AccountSummary, float64, error) {
	if len(acct.Snapshots) == 0 {
		return AccountSummary{}, 0, errors.New("no snapshots")
	}

	result, err := appeval.EvaluateLoaded(appeval.EvaluationRequest{
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

	// Build summary.
	summary := AccountSummary{
		AccountID:    acct.AccountID,
		AccountName:  acct.AccountName,
		Environment:  acct.Environment,
		BusinessUnit: acct.BusinessUnit,
		SnapshotAt:   acct.Snapshots[len(acct.Snapshots)-1].CapturedAt,
		ActiveChains: len(result.ChainFindings),
	}

	var riskScore float64
	for i := range result.Findings {
		f := &result.Findings[i]
		summary.TotalFindings++
		switch f.ControlSeverity {
		case policy.SeverityCritical:
			summary.CriticalCount++
		case policy.SeverityHigh:
			summary.HighCount++
		case policy.SeverityMedium:
			summary.MediumCount++
		case policy.SeverityLow:
			summary.LowCount++
		}
		if f.SLABreached {
			summary.SLABreached++
		}
		base := float64(risk.SeverityToWeight(f.ControlSeverity))
		dur := risk.DurationFactor(f.Evidence.UnsafeDurationHours)
		riskScore += base * dur
	}
	summary.RiskScore = math.Round(riskScore)

	return summary, riskScore, nil
}

// detectCrossAccountFindings checks for cross-account resource policy
// grants and execution role links between accounts.
func detectCrossAccountFindings(accounts []AccountInput) ([]CrossAccountFinding, int) {
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
					accountID: acct.AccountID,
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
			idx := buildResourceAccessIndex(snap)
			for ai := range snap.Assets {
				resourceARN := string(snap.Assets[ai].ID)
				resourceAcct := extractAccountID(resourceARN)
				entries := idx.EntriesFor(resourceARN)
				for _, entry := range entries {
					if entry.IsPublic {
						continue
					}
					principalAcct := extractAccountID(entry.PrincipalARN)
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
		roleAcct := extractAccountID(roleARN)
		assetAcct := extractAccountID(string(a.ID))
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

var resourcePolicyPaths = [][]string{
	{"storage", "policy_json"},
	{"encryption", "key_policy_json"},
	{"compute", "resource_policy_json"},
	{"messaging", "policy_json"},
	{"secret", "resource_policy_json"},
}

func buildResourceAccessIndex(snap *asset.Snapshot) *iam.ResourceAccessIndex {
	idx := iam.NewResourceAccessIndex()
	for i := range snap.Assets {
		a := &snap.Assets[i]
		accountID := extractAccountID(string(a.ID))
		for _, path := range resourcePolicyPaths {
			policyJSON := props.GetString(a.Properties, path)
			if policyJSON == "" {
				continue
			}
			// Non-fatal: malformed policy JSON skips annotation.
			_ = idx.AddResourcePolicy(string(a.ID), policyJSON, accountID)
		}
	}
	return idx
}

func extractAccountID(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}
