// Package rank implements the remediation roadmap — a prioritized
// work queue that transforms assessment findings into actionable
// security strategy.
package rank

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
)

// PriorityEntry represents a single finding in the remediation roadmap.
type PriorityEntry struct {
	Rank          int                 `json:"rank"`
	ControlID     kernel.ControlID    `json:"control_id"`
	ControlName   string              `json:"control_name"`
	AssetID       asset.ID            `json:"asset_id"`
	PriorityScore float64             `json:"priority_score"`
	RiskImpact    float64             `json:"risk_impact_percent"`
	Breakdown     risk.ScoreBreakdown `json:"breakdown"`
	SLAUrgency    float64             `json:"sla_urgency_multiplier"`
	SilentKiller  bool                `json:"silent_killer"`
	Narrative     string              `json:"narrative"`
	FixAction     string              `json:"fix_action,omitempty"`
}

// RemediationBundle groups findings by a shared fix action.
type RemediationBundle struct {
	Action           string             `json:"action"`
	TotalRiskReduced float64            `json:"total_risk_reduced"`
	Efficiency       float64            `json:"efficiency_score"`
	FindingCount     int                `json:"finding_count"`
	ControlIDs       []kernel.ControlID `json:"control_ids"`
}

// Roadmap is the output of BuildRoadmap.
type Roadmap struct {
	Entries   []PriorityEntry     `json:"entries"`
	Bundles   []RemediationBundle `json:"remediation_bundles,omitempty"`
	TotalRisk float64             `json:"total_risk"`
}

// SLAUrgencyMultiplier returns a multiplier based on remaining SLA time.
func SLAUrgencyMultiplier(remainingHours float64, isOverdue bool) float64 {
	if isOverdue {
		return 3.0
	}
	switch {
	case remainingHours <= 24:
		return 2.5
	case remainingHours <= 72:
		return 2.0
	case remainingHours <= 168:
		return 1.5
	default:
		return 1.0
	}
}

// BuildRoadmap creates a prioritized remediation roadmap from findings.
func BuildRoadmap(findings []remediation.Finding, topExposures []risk.ExposureRank, topN int) Roadmap {
	if len(findings) == 0 {
		return Roadmap{}
	}

	exposureByKey := make(map[string]risk.ExposureRank, len(topExposures))
	for _, te := range topExposures {
		key := string(te.ControlID) + ":" + string(te.AssetID)
		exposureByKey[key] = te
	}

	var totalRisk float64
	entries := make([]PriorityEntry, 0, len(findings))

	for i := range findings {
		f := &findings[i]
		key := string(f.ControlID) + ":" + string(f.AssetID)

		er, hasExposure := exposureByKey[key]

		var score float64
		var breakdown risk.ScoreBreakdown
		var silentKiller bool

		if hasExposure {
			score = er.ExposureScore
			breakdown = er.Breakdown
			silentKiller = er.SilentKiller
		} else {
			base := risk.SeverityToWeight(f.ControlSeverity)
			daysBlind := f.Evidence.UnsafeDurationHours / 24.0
			durFactor := risk.DurationFactor(f.Evidence.UnsafeDurationHours)
			score = float64(base) * durFactor
			breakdown = risk.ScoreBreakdown{
				BaseScore:          base,
				DurationFactor:     durFactor,
				BlastMultiplier:    1.0,
				ExposureMultiplier: 1.0,
				DaysBlind:          daysBlind,
			}
			silentKiller = daysBlind > 300
		}

		slaUrgency := 1.0
		remainingHours := f.Evidence.ThresholdHours - f.Evidence.UnsafeDurationHours
		isOverdue := f.Evidence.UnsafeDurationHours > f.Evidence.ThresholdHours && f.Evidence.ThresholdHours > 0
		if f.Evidence.ThresholdHours > 0 {
			slaUrgency = SLAUrgencyMultiplier(remainingHours, isOverdue)
		}
		score *= slaUrgency
		totalRisk += score

		fixAction := ""
		if f.RemediationSpec.Actionable() {
			fixAction = strings.TrimSpace(f.RemediationSpec.Action)
		}

		entries = append(entries, PriorityEntry{
			ControlID:     f.ControlID,
			ControlName:   f.ControlName,
			AssetID:       f.AssetID,
			PriorityScore: score,
			Breakdown:     breakdown,
			SLAUrgency:    slaUrgency,
			SilentKiller:  silentKiller,
			FixAction:     fixAction,
			Narrative:     priorityNarrative(f, breakdown, silentKiller, isOverdue),
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].PriorityScore != entries[j].PriorityScore {
			return entries[i].PriorityScore > entries[j].PriorityScore
		}
		return entries[i].ControlID < entries[j].ControlID
	})

	if totalRisk > 0 {
		for i := range entries {
			entries[i].RiskImpact = (entries[i].PriorityScore / totalRisk) * 100
			entries[i].Rank = i + 1
		}
	}

	if topN > 0 && topN < len(entries) {
		entries = entries[:topN]
	}

	bundles := buildBundles(findings, exposureByKey)

	return Roadmap{
		Entries:   entries,
		Bundles:   bundles,
		TotalRisk: totalRisk,
	}
}

func buildBundles(findings []remediation.Finding, exposureByKey map[string]risk.ExposureRank) []RemediationBundle {
	type bundleAccum struct {
		action     string
		totalScore float64
		count      int
		controls   map[kernel.ControlID]bool
	}

	accum := make(map[string]*bundleAccum)
	for i := range findings {
		f := &findings[i]
		if !f.RemediationSpec.Actionable() {
			continue
		}
		action := strings.TrimSpace(f.RemediationSpec.Action)
		if action == "" {
			continue
		}

		key := string(f.ControlID) + ":" + string(f.AssetID)
		var score float64
		if er, ok := exposureByKey[key]; ok {
			score = er.ExposureScore
		} else {
			score = float64(risk.SeverityToWeight(f.ControlSeverity))
		}

		ba, ok := accum[action]
		if !ok {
			ba = &bundleAccum{action: action, controls: make(map[kernel.ControlID]bool)}
			accum[action] = ba
		}
		ba.totalScore += score
		ba.count++
		ba.controls[f.ControlID] = true
	}

	bundles := make([]RemediationBundle, 0, len(accum))
	for _, ba := range accum {
		if ba.count < 2 {
			continue
		}
		ids := make([]kernel.ControlID, 0, len(ba.controls))
		for id := range ba.controls {
			ids = append(ids, id)
		}
		bundles = append(bundles, RemediationBundle{
			Action:           ba.action,
			TotalRiskReduced: ba.totalScore,
			Efficiency:       ba.totalScore / float64(ba.count),
			FindingCount:     ba.count,
			ControlIDs:       ids,
		})
	}

	sort.Slice(bundles, func(i, j int) bool {
		return bundles[i].TotalRiskReduced > bundles[j].TotalRiskReduced
	})

	if len(bundles) > 5 {
		bundles = bundles[:5]
	}
	return bundles
}

func priorityNarrative(f *remediation.Finding, bd risk.ScoreBreakdown, silentKiller, isOverdue bool) string {
	switch {
	case silentKiller:
		return fmt.Sprintf("Legacy exposure: %s has been misconfigured for %.0f days.", f.AssetID, bd.DaysBlind)
	case isOverdue:
		return fmt.Sprintf("SLA urgency: %s has breached the remediation policy. Immediate action required.", f.AssetID)
	case bd.BlastMultiplier > 2.0:
		return fmt.Sprintf("Detection blindness: disabling %s blinds detection across the account.", f.ControlID)
	case bd.DaysBlind > 90:
		return fmt.Sprintf("Aging exposure: %s misconfigured for %.0f days.", f.AssetID, bd.DaysBlind)
	default:
		return fmt.Sprintf("%s: %s requires remediation.", f.ControlID, f.AssetID)
	}
}
