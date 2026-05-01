// Package orgtrend computes organization-level posture trends across
// multiple accounts over time, answering "are we improving or
// regressing, and which accounts are driving the regression?"
package orgtrend

import (
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/report"
)

// Trajectory describes the direction of a score over time.
type Trajectory string

const (
	TrajectoryImproving  Trajectory = "IMPROVING"
	TrajectoryStable     Trajectory = "STABLE"
	TrajectoryRegressing Trajectory = "REGRESSING"
)

// AccountTimeSeries holds the assessment history for a single account.
type AccountTimeSeries struct {
	AccountID string
	Runs      []*report.Assessment // sorted by time
}

// Input configures the org trend computation.
type Input struct {
	Accounts []AccountTimeSeries
	Window   time.Duration
	Now      time.Time
}

// AccountTrend summarizes one account's trajectory.
type AccountTrend struct {
	AccountID    string     `json:"account_id"`
	Score        float64    `json:"score"`
	Delta        float64    `json:"delta"`
	Trajectory   Trajectory `json:"trajectory"`
	FindingCount int        `json:"finding_count"`
	CriticalOpen int        `json:"critical_open"`
	NewFindings  int        `json:"new_findings_30d"`
}

// ChainActivation records a chain active across multiple accounts.
type ChainActivation struct {
	ChainID     string `json:"chain_id"`
	ActiveCount int    `json:"active_count"`
	TotalCount  int    `json:"total_count"`
	Severity    string `json:"severity,omitempty"`
}

// RegressionDriver describes why an account is regressing.
type RegressionDriver struct {
	AccountID   string `json:"account_id"`
	Description string `json:"description"`
}

// OrgTrendReport is the output of org-level trending.
type OrgTrendReport struct {
	GeneratedAt       time.Time          `json:"generated_at"`
	AccountCount      int                `json:"account_count"`
	WindowDays        int                `json:"window_days"`
	OrgScore          float64            `json:"org_score"`
	OrgDelta          float64            `json:"org_delta"`
	OrgTrajectory     Trajectory         `json:"org_trajectory"`
	Accounts          []AccountTrend     `json:"accounts"`
	RegressionDrivers []RegressionDriver `json:"regression_drivers,omitempty"`
	ChainActivations  []ChainActivation  `json:"chain_activations,omitempty"`
}

// Compute produces the org-level trend report.
func Compute(in Input) *OrgTrendReport {
	result := &OrgTrendReport{
		GeneratedAt:  in.Now,
		AccountCount: len(in.Accounts),
		WindowDays:   int(in.Window.Hours() / 24),
	}

	if len(in.Accounts) == 0 {
		return result
	}

	cutoff := in.Now.Add(-in.Window)

	var totalScore, totalDelta float64
	var totalWeight float64
	chainCounts := make(map[string]*ChainActivation)

	for _, acct := range in.Accounts {
		// Filter to window.
		var inWindow []*report.Assessment
		for _, a := range acct.Runs {
			if !a.Run.Now.Before(cutoff) {
				inWindow = append(inWindow, a)
			}
		}
		if len(inWindow) == 0 {
			continue
		}

		slices.SortFunc(inWindow, func(a, b *report.Assessment) int {
			return a.Run.Now.Compare(b.Run.Now)
		})

		latest := inWindow[len(inWindow)-1]
		earliest := inWindow[0]

		latestScore := computeScore(latest)
		earliestScore := computeScore(earliest)
		delta := latestScore - earliestScore

		// Count new findings in recent 30 days.
		recentCutoff := in.Now.Add(-30 * 24 * time.Hour)
		newFindings := countNewFindings(inWindow, recentCutoff)

		// Count critical findings.
		criticalOpen := countBySeverity(latest.Findings, "critical")

		at := AccountTrend{
			AccountID:    acct.AccountID,
			Score:        math.Round(latestScore*10) / 10,
			Delta:        math.Round(delta*10) / 10,
			Trajectory:   classifyTrajectory(delta),
			FindingCount: len(latest.Findings),
			CriticalOpen: criticalOpen,
			NewFindings:  newFindings,
		}
		result.Accounts = append(result.Accounts, at)

		// Weighted contribution to org score.
		weight := float64(max(len(latest.Findings), 1))
		totalScore += latestScore * weight
		totalDelta += delta * weight
		totalWeight += weight

		// Track chain activations.
		for i := range latest.ChainFindings {
			cf := &latest.ChainFindings[i]
			cid := string(cf.ChainID)
			ca, exists := chainCounts[cid]
			if !exists {
				ca = &ChainActivation{
					ChainID:    cid,
					TotalCount: len(in.Accounts),
					Severity:   cf.Severity.String(),
				}
				chainCounts[cid] = ca
			}
			ca.ActiveCount++
		}

		// Identify regression drivers.
		if at.Trajectory == TrajectoryRegressing {
			desc := describeRegression(at, in.Window)
			result.RegressionDrivers = append(result.RegressionDrivers, RegressionDriver{
				AccountID:   acct.AccountID,
				Description: desc,
			})
		}
	}

	// Compute org aggregate.
	if totalWeight > 0 {
		result.OrgScore = math.Round(totalScore/totalWeight*10) / 10
		result.OrgDelta = math.Round(totalDelta/totalWeight*10) / 10
	}
	result.OrgTrajectory = classifyTrajectory(result.OrgDelta)

	// Sort accounts by score ascending (worst first).
	slices.SortFunc(result.Accounts, func(a, b AccountTrend) int {
		if a.Score != b.Score {
			if a.Score < b.Score {
				return -1
			}
			return 1
		}
		return 0
	})

	// Collect chain activations.
	for _, ca := range chainCounts {
		if ca.ActiveCount > 0 {
			result.ChainActivations = append(result.ChainActivations, *ca)
		}
	}
	slices.SortFunc(result.ChainActivations, func(a, b ChainActivation) int {
		return b.ActiveCount - a.ActiveCount
	})

	return result
}

// computeScore derives a 0-100 posture score from an assessment.
// Higher is better: 100 means no findings.
func computeScore(a *report.Assessment) float64 {
	if a.Summary.TotalAssets == 0 {
		return 100
	}
	violationRate := float64(a.Summary.Violations) / float64(a.Summary.TotalAssets)
	score := (1.0 - violationRate) * 100
	return math.Max(0, math.Min(100, score))
}

func classifyTrajectory(delta float64) Trajectory {
	switch {
	case delta >= 3.0:
		return TrajectoryImproving
	case delta <= -3.0:
		return TrajectoryRegressing
	default:
		return TrajectoryStable
	}
}

// countNewFindings counts findings in the latest assessment that were
// not present in any earlier assessment within the cutoff.
func countNewFindings(sorted []*report.Assessment, cutoff time.Time) int {
	if len(sorted) < 2 {
		return 0
	}

	latest := sorted[len(sorted)-1]

	// Build set of all historical finding keys.
	type fkey struct{ ctl, ast string }
	historical := make(map[fkey]bool)
	for _, a := range sorted[:len(sorted)-1] {
		if a.Run.Now.Before(cutoff) {
			continue
		}
		for i := range a.Findings {
			historical[fkey{
				ctl: string(a.Findings[i].ControlID),
				ast: string(a.Findings[i].AssetID),
			}] = true
		}
	}

	newCount := 0
	for i := range latest.Findings {
		k := fkey{
			ctl: string(latest.Findings[i].ControlID),
			ast: string(latest.Findings[i].AssetID),
		}
		if !historical[k] {
			newCount++
		}
	}
	return newCount
}

func countBySeverity(findings []remediation.Finding, sev string) int {
	count := 0
	for i := range findings {
		if findings[i].ControlSeverity.String() == sev {
			count++
		}
	}
	return count
}

func describeRegression(at AccountTrend, window time.Duration) string {
	days := int(window.Hours() / 24)
	if at.NewFindings > 0 {
		return fmt.Sprintf("+%d new findings in last 30d, score down %.1f in %dd", at.NewFindings, -at.Delta, days)
	}
	return fmt.Sprintf("score down %.1f in %dd, %d findings open", -at.Delta, days, at.FindingCount)
}
