// Package text provides text-based output functionality for evaluation results.
// It handles formatting and writing of findings as human-readable text.
package text

import (
	"bytes"
	"strings"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/env"
	"github.com/sufield/stave/internal/platform/crypto"
)

// FindingWriter marshals findings as human-readable text.
type FindingWriter struct{}

var _ appcontracts.FindingMarshaler = (*FindingWriter)(nil)

// MarshalFindings transforms enriched findings into human-readable text bytes
// without performing I/O.
func (w *FindingWriter) MarshalFindings(enriched *appcontracts.EnrichedResult) ([]byte, error) {
	var buf bytes.Buffer
	d := &drawer{w: &buf}
	result := enriched.Result

	w.writeHeader(d, &result)
	if len(result.Findings) == 0 {
		w.writeNoViolationsSummary(d)
		if d.err != nil {
			return nil, d.err
		}
		return buf.Bytes(), nil
	}

	remFindings := toRemediationFindings(enriched.Findings)
	w.writeViolationsFromEnriched(d, &result, remFindings)
	w.writeChainFindings(d, &result)
	w.writeAttackStageSummary(d, &result)
	w.writeTopExposures(d, &result)
	w.writeFrameworkReadiness(d, &result)
	w.writeRemediationGroups(d, remFindings)
	w.writeSkippedControls(d, result.SkippedControls)
	writeExemptedAssets(d, enriched.ExemptedAssets)
	w.writeExceptedFindings(d, result.ExceptedFindings)
	if !env.Demo.IsTrue() {
		d.f("\nNext step: run `stave diagnose --controls <dir> --observations <dir>` for root-cause guidance.\n")
	}

	if d.err != nil {
		return nil, d.err
	}
	return buf.Bytes(), nil
}

func (w *FindingWriter) writeHeader(d *drawer, result *evaluation.ComplianceReport) {
	d.ln("Evaluation Results")
	d.ln("==================")
	d.f("\nRun: %s (max-unsafe: %s, snapshots: %d)\n\n",
		result.Run.Now.Format("2006-01-02 15:04:05 UTC"),
		result.Run.MaxUnsafeDuration.String(),
		result.Run.Snapshots)
	d.ln("Summary")
	d.ln("-------")
	d.f("  Assets evaluated:    %d\n", result.Summary.TotalAssets)
	d.f("  Attack surface:      %d\n", result.Summary.ExposedResources)
	d.f("  Violations:          %d\n\n", result.Summary.Violations)
}

func (w *FindingWriter) writeNoViolationsSummary(d *drawer) {
	d.f("No violations found.\n")
	if !env.Demo.IsTrue() {
		d.f("\nNext step: run `stave verify` after remediation snapshots to confirm no regressions.\n")
	}
}

// writeViolationsFromEnriched renders violation output from pre-enriched findings.
func (w *FindingWriter) writeViolationsFromEnriched(d *drawer, result *evaluation.ComplianceReport, enriched []remediation.Finding) {
	d.ln("Violations")
	d.ln("----------")
	w.writeViolationDomainSummary(d, result.Checks)

	if d.err != nil {
		return
	}

	for i := range enriched {
		f := &enriched[i]
		w.writeFinding(d, i+1, *f)
	}
}

func (w *FindingWriter) writeSkippedControls(d *drawer, skipped []evaluation.SkippedControl) {
	if len(skipped) == 0 {
		return
	}
	d.f("\nSkipped Controls: %d\n", len(skipped))
	for _, s := range skipped {
		d.f("  - %s: %s\n", s.ControlID, s.Reason)
	}
}

func writeExemptedAssets(d *drawer, skipped []asset.ExemptedAsset) {
	if len(skipped) == 0 {
		return
	}
	d.f("\nExempted Assets: %d\n", len(skipped))
	for _, s := range skipped {
		d.f("  - %s: %s\n", s.ID, s.Reason)
	}
}

func (w *FindingWriter) writeExceptedFindings(d *drawer, excepted []evaluation.ExceptedFinding) {
	if len(excepted) == 0 {
		return
	}
	d.f("\nExcepted Findings: %d\n", len(excepted))
	for _, s := range excepted {
		d.f("  - %s on %s: %s", s.ControlID, s.AssetID, s.Reason)
		if !s.Expires.IsZero() {
			d.f(" (expires %s)", s.Expires.String())
		}
		d.f("\n")
	}
}

func (w *FindingWriter) writeViolationDomainSummary(d *drawer, rows []evaluation.ResourceCheck) {
	domainCounts := GroupViolationsByDomain(rows)
	if len(domainCounts) == 0 {
		return
	}

	d.ln("  By domain:")
	for _, dc := range domainCounts {
		d.f("    - %s: %d\n", string(dc.Domain), dc.Count)
	}
	d.f("\n")
}

// writeRemediationGroups renders a summary of remediation groups when at least
// one group has more than one contributing control.
func (w *FindingWriter) writeRemediationGroups(d *drawer, enriched []remediation.Finding) {
	h := crypto.NewHasher()
	remediation.PrepareForGrouping(h, h, enriched)
	groups := remediation.BuildGroups(enriched)
	totalFindings, hasMulti := remediation.GroupStats(groups)
	if len(groups) == 0 || !hasMulti {
		return
	}
	writeRemediationGroupHeader(d, len(groups), totalFindings)
	writeRemediationGroupRows(d, groups)
}

func writeRemediationGroupHeader(d *drawer, groupCount, totalFindings int) {
	d.f("\nRemediation Groups (%d distinct fix plans across %d findings)\n", groupCount, totalFindings)
	d.f("------------------------------------------------------------\n")
}

func writeRemediationGroupRows(d *drawer, groups []remediation.Group) {
	for i := range groups {
		group := &groups[i]
		d.f("  %d. %s (%s)\n", i+1, group.AssetID, group.AssetType)
		d.f("     Resolves %d findings: %s\n", group.FindingCount, joinControls(group.ContributingControls))
		d.f("     Actions: set %d properties\n", len(group.RemediationPlan.Actions))
	}
}

func joinControls(ids []kernel.ControlID) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = string(id)
	}
	return strings.Join(parts, ", ")
}

// writeFinding writes a single finding in text format.
func (w *FindingWriter) writeFinding(d *drawer, num int, f remediation.Finding) {
	writeFindingHeader(d, num, f)
	writeFindingSource(d, f)
	writeFindingEvidence(d, f)
	writeFindingRemediation(d, f)
}

func writeFindingHeader(d *drawer, num int, f remediation.Finding) {
	d.f("\n%d. %s\n", num, f.ControlID)
	d.f("   %s\n", f.ControlName)
	d.f("   Asset: %s (%s/%s)\n", f.AssetID, f.AssetVendor, f.AssetType)
}

func writeFindingSource(d *drawer, f remediation.Finding) {
	if f.Source == nil {
		return
	}
	d.f("   Source: %s:%d\n", f.Source.File, f.Source.Line)
}

func writeFindingEvidence(d *drawer, f remediation.Finding) {
	d.f("   Evidence:\n")
	writeFindingEvidenceLifecycle(d, f)
	writeFindingEvidenceContext(d, f)
}

func writeFindingEvidenceLifecycle(d *drawer, f remediation.Finding) {
	if !f.Evidence.FirstUnsafeAt.IsZero() {
		d.f("     First unsafe: %s\n", f.Evidence.FirstUnsafeAt.Format("2006-01-02 15:04:05 UTC"))
	}
	if !f.Evidence.LastSeenUnsafeAt.IsZero() {
		d.f("     Last seen:    %s\n", f.Evidence.LastSeenUnsafeAt.Format("2006-01-02 15:04:05 UTC"))
	}
	if f.Evidence.UnsafeDurationHours > 0 {
		d.f("     Duration:     %.0fh (threshold: %.0fh)\n", f.Evidence.UnsafeDurationHours, f.Evidence.ThresholdHours)
	}
}

func writeFindingEvidenceContext(d *drawer, f remediation.Finding) {
	if f.Evidence.ExposureWindowCount > 0 {
		d.f("     Exposure Windows:     %d (limit: %d within %d days)\n", f.Evidence.ExposureWindowCount, f.Evidence.RecurrenceLimit, f.Evidence.WindowDays)
	}
	if f.Evidence.TemporalRisk != "" {
		d.f("     Why now:      %s\n", f.Evidence.TemporalRisk)
	}
}

func writeFindingRemediation(d *drawer, f remediation.Finding) {
	if f.RemediationSpec.Description == "" && f.RemediationSpec.Action == "" {
		return
	}
	d.f("   Remediation:\n")
	if f.RemediationSpec.Description != "" {
		d.f("     %s\n", f.RemediationSpec.Description)
	}
	if f.RemediationSpec.Action != "" {
		d.f("     Action: %s\n", f.RemediationSpec.Action)
	}
}

// toRemediationFindings converts port-boundary enriched findings to
// remediation.Finding for use by core formatting functions.
func toRemediationFindings(fs []appcontracts.EnrichedFinding) []remediation.Finding {
	out := make([]remediation.Finding, len(fs))
	for i := range fs {
		f := &fs[i]
		out[i] = remediation.Finding{
			Finding:         f.Finding,
			RemediationSpec: f.RemediationSpec,
			RemediationPlan: f.RemediationPlan,
		}
	}
	return out
}

func (w *FindingWriter) writeChainFindings(d *drawer, result *evaluation.ComplianceReport) {
	if len(result.ChainFindings) == 0 {
		return
	}
	d.f("\nCompound Risk Chains")
	d.f("\n--------------------\n")
	for i := range result.ChainFindings {
		cf := &result.ChainFindings[i]
		d.f("\n  [%s] Chain: %s\n", cf.Severity, cf.ChainID)
		if cf.Description != "" {
			d.f("  %s\n", strings.TrimSpace(cf.Description))
		}
		d.f("  Failing:    %s\n", strings.Join(controlIDStrings(cf.ControlsFailing), ", "))
		if len(cf.MissingSafeguards) > 0 {
			d.f("  Fix any of: %s\n", strings.Join(controlIDStrings(cf.MissingSafeguards), ", "))
		}
		d.f("  Score:      %.1f\n", cf.CompoundScore)
		if len(cf.AttackStages) > 0 {
			d.f("  Stages:     %s\n", strings.Join(cf.AttackStages, ", "))
		}
	}
}

func (w *FindingWriter) writeAttackStageSummary(d *drawer, result *evaluation.ComplianceReport) {
	if len(result.AttackStageSummary) == 0 {
		return
	}
	d.f("\nAttack Stage Summary")
	d.f("\n--------------------\n")
	for _, stage := range []string{
		"initial_access", "credential_access", "persistence",
		"exfiltration", "detection_evasion", "resilience",
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
	d.f("\nTop Exposures")
	d.f("\n-------------\n")
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
		d.f("  base=%d \u00d7 duration=%.1f \u00d7 blast=%.1f \u00d7 exposure=%.1f\n",
			b.BaseScore, b.DurationFactor, b.BlastMultiplier, b.ExposureMultiplier)
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
