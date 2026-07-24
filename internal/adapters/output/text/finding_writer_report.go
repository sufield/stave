package text

import (
	"strings"

	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

func (w *FindingWriter) writeChainFindings(d *drawer, result *evaluation.ComplianceReport) {
	if len(result.ChainFindings) == 0 {
		return
	}
	d.f("\nCompound Risk Chains")
	d.f("\n--------------------\n")
	for i := range result.ChainFindings {
		cf := &result.ChainFindings[i]
		d.f("\n  [%s] Chain: %s\n", cf.SeverityLabel(), cf.ChainID)
		if cf.Description != "" {
			d.f("  %s\n", strings.TrimSpace(cf.Description))
		}
		d.f("  Failing:    %s\n", strings.Join(controlIDStrings(cf.ControlsFailing), ", "))
		if len(cf.MissingSafeguards) > 0 {
			d.f("  Fix any of: %s\n", strings.Join(controlIDStrings(cf.MissingSafeguards), ", "))
		}
		d.f("  Score:      %.1f\n", cf.CompoundScore)
		if len(cf.AttackStages) > 0 {
			d.f("  Stages:     %s\n", strings.Join(attackStageStrings(cf.AttackStages), ", "))
		}
	}
}

func (w *FindingWriter) writeAttackStageSummary(d *drawer, result *evaluation.ComplianceReport) {
	if len(result.AttackStageSummary) == 0 {
		return
	}
	d.f("\nAttack Stage Summary")
	d.f("\n--------------------\n")
	for _, stage := range []kernel.AttackStage{
		kernel.AttackStageInitialAccess, kernel.AttackStageExecution,
		kernel.AttackStageCredentialAccess, kernel.AttackStagePersistence,
		kernel.AttackStageCollection, kernel.AttackStageExfiltration,
		kernel.AttackStageDetectionEvasion, kernel.AttackStageResilience,
	} {
		status, ok := result.AttackStageSummary[stage]
		if !ok {
			continue
		}
		d.f("  %-20s %s\n", stage, status)
	}
}

func (w *FindingWriter) writeTopExposures(d *drawer, result *evaluation.ComplianceReport) {
	if len(result.TopExposures) == 0 {
		return
	}
	// The main findings list is already sorted by ExposureScore
	// descending (see evaluation.SortFindings). This section is
	// retained as an at-a-glance "address these first" summary —
	// same items the reader sees at the top of the list, re-rendered
	// with the full score breakdown inline for a quick read without
	// scrolling through per-finding evidence blocks.
	d.f("\nCritical-Path Exposures (address first)")
	d.f("\n---------------------------------------\n")
	limit := min(len(result.TopExposures), 10)
	for i := range limit {
		r := &result.TopExposures[i]
		d.f("  %2d  %7.1f  %5.0fd  %-30s %s\n",
			i+1, r.ExposureScore, r.Breakdown.DaysBlind,
			string(r.ControlID), string(r.AssetID))
		b := &r.Breakdown
		if r.SilentKiller {
			d.f("      SILENT KILLER")
		} else {
			d.f("     ")
		}
		d.f("  base=%d \u00d7 duration=%.1f \u00d7 blast=%.1f \u00d7 exposure=%.1f \u00d7 chain=%.1f\n",
			b.BaseScore, b.DurationFactor, b.BlastMultiplier, b.ExposureMultiplier, b.ChainBonus)
	}
}

func (w *FindingWriter) writeFrameworkReadiness(d *drawer, result *evaluation.ComplianceReport) {
	readiness := result.Summary.FrameworkReadiness
	if len(readiness) == 0 {
		return
	}
	d.f("\nFramework Readiness")
	d.f("\n-------------------\n")
	for i := range readiness {
		r := &readiness[i]
		if r.TotalControls == 0 {
			// No controls mapped for this requested framework: show the
			// gap explicitly so 0% is not misread as "failing every
			// control" (and never as the old false 100%).
			d.f("  %-20s   --  (no controls mapped)\n", r.Framework)
			continue
		}
		d.f("  %-20s %3d%%  (%d/%d controls passing)\n",
			r.Framework, r.ReadinessPercent, r.PassingControls, r.TotalControls)
	}
	if result.Summary.FrameworkCitationsSatisfied > 0 {
		d.f("\nCompliance ROI: fixing %d violations covers %d framework citations\n",
			result.Summary.Violations, result.Summary.FrameworkCitationsSatisfied)
	}
	if sf := result.Summary.SuperFix; sf != nil {
		d.f("\n[!] High-Impact Remediation: fixing %s satisfies %d requirements across %s\n",
			string(sf.ControlID), sf.CitationsFixed, strings.Join(sf.Frameworks, ", "))
	}
	if len(result.Summary.NearbyFrameworks) > 0 {
		d.f("\nNearby Frameworks (already >80%% ready)\n")
		for i := range result.Summary.NearbyFrameworks {
			nf := &result.Summary.NearbyFrameworks[i]
			d.f("  %-20s %3d%% ready (%d gaps to close)\n",
				nf.Framework, nf.ReadinessPercent, nf.GapCount)
		}
	}
}

func controlIDStrings(ids []kernel.ControlID) []string {
	s := make([]string, len(ids))
	for i, id := range ids {
		s[i] = string(id)
	}
	return s
}

func attackStageStrings(stages []kernel.AttackStage) []string {
	s := make([]string, len(stages))
	for i, st := range stages {
		s[i] = string(st)
	}
	return s
}
