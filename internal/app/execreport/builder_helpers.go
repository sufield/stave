package execreport

import (
	"context"
	"sort"
	"strings"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appcoverage "github.com/sufield/stave/internal/app/coverage"
	"github.com/sufield/stave/internal/app/teams"
	"github.com/sufield/stave/internal/core/evaluation"
	corereport "github.com/sufield/stave/internal/core/report"
)

// countFindings tallies findings by severity tier on the assessment.
// The total includes every finding; the per-severity counts only
// include the four named tiers.
func countFindings(a *corereport.Assessment) FindingsSummary {
	var fs FindingsSummary
	fs.Total = len(a.Findings)
	for i := range a.Findings {
		switch a.Findings[i].ControlSeverity.BucketName() {
		case "critical":
			fs.Critical++
		case "high":
			fs.High++
		case "medium":
			fs.Medium++
		case "low":
			fs.Low++
		}
	}
	return fs
}

// buildSLASection summarizes SLA compliance for findings whose
// severity has a deadline in cfg. Returns nil when cfg is nil so the
// report's SLA block is omitted.
func buildSLASection(a *corereport.Assessment, cfg *evaluation.SLAConfig) *SLASection {
	if cfg == nil {
		return nil
	}
	bySev := make(map[string]SLASev)
	burnRates := make(map[string]float64)
	burnCounts := make(map[string]int)
	totalWithin, totalAll := 0, 0

	for i := range a.Findings {
		f := &a.Findings[i]
		sev := strings.ToLower(f.ControlSeverity.String())
		deadline := cfg.DeadlineBySeverity[sev]
		if deadline <= 0 {
			continue
		}
		s := bySev[sev]
		s.Total++
		totalAll++
		if !f.SLABreached {
			s.Within++
			totalWithin++
		} else {
			s.Breached++
		}
		bySev[sev] = s
		burnRates[sev] += f.Evidence.UnsafeDurationHours / deadline
		burnCounts[sev]++
	}

	for sev, s := range bySev {
		if s.Total > 0 {
			s.Pct = float64(s.Within) / float64(s.Total) * 100
		}
		bySev[sev] = s
	}
	for sev := range burnRates {
		if burnCounts[sev] > 0 {
			burnRates[sev] /= float64(burnCounts[sev])
		}
	}

	overallPct := 100.0
	if totalAll > 0 {
		overallPct = float64(totalWithin) / float64(totalAll) * 100
	}

	return &SLASection{
		ProfileName:   cfg.ProfileID,
		CompliancePct: overallPct,
		BySeverity:    bySev,
		BurnRates:     burnRates,
	}
}

// buildTopFindings returns the n highest-priority findings by a
// severity-weighted score (severity tier × 100 + SLA burn rate × 50).
// Used by the report's "Top Findings" section.
func buildTopFindings(a *corereport.Assessment, n int) []TopFinding {
	type ranked struct {
		idx   int
		score float64
	}
	sevWeight := map[string]float64{"critical": 4, "high": 3, "medium": 2, "low": 1}
	var items []ranked
	for i := range a.Findings {
		f := &a.Findings[i]
		w := sevWeight[strings.ToLower(f.ControlSeverity.String())]
		burn := 0.0
		if f.SLADeadlineHours != nil && *f.SLADeadlineHours > 0 {
			burn = f.Evidence.UnsafeDurationHours / *f.SLADeadlineHours
		}
		items = append(items, ranked{idx: i, score: w*100 + burn*50})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].score > items[j].score })
	if len(items) > n {
		items = items[:n]
	}
	var result []TopFinding
	for rank, item := range items {
		f := &a.Findings[item.idx]
		tf := TopFinding{
			Rank:        rank + 1,
			ControlID:   string(f.ControlID),
			Severity:    f.ControlSeverity.String(),
			AssetID:     string(f.AssetID),
			DwellHours:  f.Evidence.UnsafeDurationHours,
			SLABreached: f.SLABreached,
		}
		if f.SLADeadlineHours != nil && *f.SLADeadlineHours > 0 {
			tf.SLABurnRate = f.Evidence.UnsafeDurationHours / *f.SLADeadlineHours
		}
		result = append(result, tf)
	}
	return result
}

// buildChainsSection summarizes detected attack chains.
func buildChainsSection(a *corereport.Assessment) ChainsSection {
	var active []ActiveChain
	for i := range a.ChainFindings {
		cf := &a.ChainFindings[i]
		var members []string
		for _, cid := range cf.ControlsFailing {
			members = append(members, string(cid))
		}
		active = append(active, ActiveChain{
			ChainID:   string(cf.ChainID),
			Severity:  cf.Severity.String(),
			Members:   members,
			Narrative: cf.Narrative,
		})
	}
	return ChainsSection{
		ActiveCount: len(active),
		Active:      active,
	}
}

// buildATTCKSection wires the ATT&CK coverage block. Reads the
// control catalog directly via the repo port. Errors at load time
// degrade to an empty report rather than failing the whole build —
// ATT&CK coverage is decorative.
func buildATTCKSection(ctx context.Context, repo appcontracts.ControlRepository, controlsDir string) AttackCoverageSection {
	total := len(appcoverage.AllTactics)

	emptyReport := func(status string) AttackCoverageSection {
		tactics := make([]TacticItem, 0, total)
		for _, td := range appcoverage.AllTactics {
			tactics = append(tactics, TacticItem{
				ID:     td.ID,
				Name:   td.Name,
				Status: status,
			})
		}
		return AttackCoverageSection{
			TacticsCovered: 0,
			TacticsTotal:   total,
			CoveragePct:    0,
			ByTactic:       tactics,
		}
	}

	if controlsDir == "" || repo == nil {
		return emptyReport("not_covered")
	}
	controls, err := repo.LoadControls(ctx, controlsDir)
	if err != nil {
		return emptyReport("not_covered")
	}

	report := appcoverage.Build(appcoverage.BuildInput{Controls: controls})
	tacticItems := make([]TacticItem, 0, len(report.Tactics))
	covered := 0
	for i := range report.Tactics {
		tc := &report.Tactics[i]
		status := tc.Status
		if status == "no_coverage" {
			status = "not_covered"
		}
		if tc.Status == "covered" || tc.Status == "thin" {
			covered++
		}
		tacticItems = append(tacticItems, TacticItem{
			ID:     tc.TacticID,
			Name:   tc.TacticName,
			Status: status,
		})
	}
	pct := 0.0
	if total > 0 {
		pct = float64(covered) / float64(total) * 100
	}
	return AttackCoverageSection{
		TacticsCovered: covered,
		TacticsTotal:   total,
		CoveragePct:    pct,
		ByTactic:       tacticItems,
	}
}

// buildTeamSections aggregates open and critical-open findings per
// team in the manifest. Findings without an owner are tallied under
// the empty-string team ID; the manifest's section list determines
// the visible output.
func buildTeamSections(a *corereport.Assessment, manifest *teams.Manifest) []TeamSection {
	teamFindings := make(map[string]int)
	teamCritical := make(map[string]int)
	for i := range a.Findings {
		f := &a.Findings[i]
		owner := manifest.ResolveOwner(nil, string(f.AssetID), string(f.ControlID))
		teamFindings[owner.TeamID]++
		if strings.EqualFold(f.ControlSeverity.String(), "critical") {
			teamCritical[owner.TeamID]++
		}
	}

	var sections []TeamSection
	for i := range manifest.Teams {
		t := &manifest.Teams[i]
		sections = append(sections, TeamSection{
			ID:           t.ID,
			Name:         t.DisplayName,
			OpenFindings: teamFindings[t.ID],
			CriticalOpen: teamCritical[t.ID],
			Contact:      t.Contact,
		})
	}
	return sections
}
