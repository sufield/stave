package text

import (
	"fmt"
	"strings"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/translation"
)

// writeChainMemberFinding writes a finding that is part of an active attack chain.
func (w *FindingWriter) writeChainMemberFinding(d *drawer, num int, f *remediation.Finding) {
	d.f("\n%d. [ATTACK PATH] %s  %s\n", num, f.PrimaryChainID(), f.PrimaryChainSeverity())
	d.f("   %s  %s\n", f.ControlID, f.AssetID)
	if risk := f.TemporalRiskMessage(); risk != "" {
		d.f("   %s\n", risk)
	}
	narrative := strings.TrimSpace(f.PrimaryChainNarrative())
	if narrative != "" {
		d.f("   Chain: %s\n", narrative)
	}
}

// writeOneAwayFinding writes a finding that is one control short of completing a chain.
func (w *FindingWriter) writeOneAwayFinding(d *drawer, num int, f *remediation.Finding) {
	d.f("\n%d. [ONE AWAY] %s  %s\n", num, f.ControlSeverity, f.ControlID)
	d.f("   %s\n", f.ControlName)
	d.f("   Asset: %s (%s/%s)\n", f.AssetID, f.AssetVendor, f.AssetType)
	for _, nm := range f.NearMissChains {
		d.f("   Chain %s\n", nm.ChainID)
		if len(nm.ControlsFailing) > 0 {
			d.f("     FAILING (%d %s active):\n",
				len(nm.ControlsFailing), pluralize(len(nm.ControlsFailing), "prerequisite", "prerequisites"))
			for _, cid := range nm.ControlsFailing {
				d.f("       ✗ %s\n", cid)
			}
		}
		d.f("     HOLDING (gate preventing full exploitation):\n")
		d.f("       ✓ %s\n", nm.MissingControl)
	}
}

// writeIsolatedFinding writes a finding not part of any active attack chain.
// When showLabel is true, appends an isolation label to distinguish from
// chain-member findings listed above.
func (w *FindingWriter) writeIsolatedFinding(d *drawer, num int, f *remediation.Finding, showLabel bool) {
	writeFindingHeader(d, num, f)
	if showLabel {
		d.f("   (isolated finding \u2014 not part of any active attack path)\n")
	}
	writeFindingSource(d, f)
	writeFindingAlternatives(d, f)
	writeFindingEvidence(d, f)
	writeFindingReasoning(d, f)
	writeFindingTriage(d, f)
	writeFindingObserved(d, f)
	writeFindingDelta(d, f)
	writeFindingRemediation(d, f)
}

// writeFindingAlternatives renders one line per alternative-tool check
// the control covers, e.g.,
//
//	Alternative: prowler/s3_bucket_acl_prohibited (covered)
//
// Silent when the control declares no alternatives. The Note field is
// not rendered in text output to keep finding headers compact; full
// note text remains in JSON output.
func writeFindingAlternatives(d *drawer, f *remediation.Finding) {
	if !f.HasAlternatives() {
		return
	}
	for _, a := range f.Alternatives {
		d.f("   Alternative: %s/%s (%s)\n", a.Tool, a.CheckID, a.Coverage)
	}
}

func writeFindingHeader(d *drawer, num int, f *remediation.Finding) {
	d.f("\n%d. %s\n", num, f.ControlID)
	d.f("   %s\n", f.ControlName)
	d.f("   Asset: %s (%s/%s)\n", f.AssetID, f.AssetVendor, f.AssetType)
}

func writeFindingSource(d *drawer, f *remediation.Finding) {
	if !f.HasSource() {
		return
	}
	d.f("   Source: %s:%d\n", f.Source.File, f.Source.Line)
}

func writeFindingEvidence(d *drawer, f *remediation.Finding) {
	d.f("   Evidence:\n")
	writeFindingEvidenceLifecycle(d, f)
	writeFindingEvidenceContext(d, f)
}

func writeFindingEvidenceLifecycle(d *drawer, f *remediation.Finding) {
	// IsTemporallySignificant gates the entire block: a finding
	// without lifecycle dates AND without measured dwell is an
	// unanchored noise event — skip the section entirely so the
	// renderer doesn't print three empty lines for a first-run
	// observation that hasn't accumulated weight yet.
	if !f.IsTemporallySignificant() {
		return
	}
	snap := f.Evidence.TemporalSnapshot()
	if snap.HasDiscoveryDate() {
		d.f("     First unsafe: %s\n", snap.FirstUnsafeAt.Format("2006-01-02 15:04:05 UTC"))
	}
	if snap.HasRecentActivity() {
		d.f("     Last seen:    %s\n", snap.LastSeenUnsafeAt.Format("2006-01-02 15:04:05 UTC"))
	}
	if snap.IsDurationTracked() {
		d.f("     Duration:     %.0fh (threshold: %.0fh)\n", snap.UnsafeDurationHours, snap.ThresholdHours)
	}
}

func writeFindingEvidenceContext(d *drawer, f *remediation.Finding) {
	if f.Evidence.HasExposureWindows() {
		d.f("     Exposure Windows:     %d (limit: %d within %d days)\n", f.Evidence.ExposureWindowCount, f.Evidence.RecurrenceThreshold, f.Evidence.WindowDays)
	}
	if msg := f.TemporalRiskMessage(); msg != "" {
		d.f("     Why now:      %s\n", msg)
	}
}

// writeIssues renders the Issues section — consolidated view of
// findings sharing a root-cause signal per asset. Emitted ahead of
// the findings list so readers see the reduced triage set first;
// per-control detail stays in the findings list below. See
// docs/product/metrics.md § Metric 2.
func (w *FindingWriter) writeIssues(d *drawer, result *evaluation.ComplianceReport) {
	issues := result.Issues
	if len(issues) == 0 {
		return
	}
	// Skip when every Issue is a singleton — there's nothing consolidated
	// to show and the findings list below carries the same information.
	anyMulti := false
	for i := range issues {
		if len(issues[i].MemberFindingIDs) > 1 {
			anyMulti = true
			break
		}
	}
	if !anyMulti {
		return
	}

	d.f("\nIssues (consolidated by shared root cause)")
	d.f("\n------------------------------------------\n")
	for i := range issues {
		iss := &issues[i]
		d.f("\n%d. %s  (%d %s)\n", i+1, iss.AssetID, len(iss.MemberFindingIDs), pluralize(len(iss.MemberFindingIDs), "finding", "findings"))
		d.f("   Score: %.1f\n", iss.ConsolidatedScore.Value())
		sharedStrs := make([]string, len(iss.SharedKeys))
		for j, k := range iss.SharedKeys {
			sharedStrs[j] = k.String()
		}
		d.f("   Root cause: %s\n", strings.Join(sharedStrs, ", "))
		d.f("   Members:\n")
		for _, fid := range iss.MemberFindingIDs {
			if f, ok := result.FindByID(string(fid)); ok {
				d.f("     - %s (%s)\n", f.ControlID, f.AssetID)
			} else {
				d.f("     - %s\n", fid)
			}
		}
	}
}

func pluralize(n int, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
}

// writeFindingReasoning renders the inline reasoning trace — the
// predicate clauses the engine evaluated and the observed values it
// saw — translated into plain English per
// docs/product/metrics.md § Metric 5.
//
// Clauses are partitioned by translation.ClassifyClause into two
// sections: "Scope:" lists predicate gates (asset-class
// discriminators, parameterized constraints) that select which
// assets the predicate applies to; "Reasoning:" lists unsafe-match
// clauses that identify the unsafe condition. The split lets the
// reader see at a glance which clauses point at the violation. Empty
// sections are suppressed.
//
// Silent when the finding has no backing predicate (e.g., compound-
// chain findings with no extractable clauses). JSON and SARIF output
// retain the raw DSL shape; prose is a text-writer concern.
func writeFindingReasoning(d *drawer, f *remediation.Finding) {
	if !f.HasReasoningTrace() {
		return
	}
	var scope, reasoning []translation.Clause
	for _, mc := range f.ReasoningTrace {
		key := mc.ObservationKey.String()
		c := translation.Clause{
			ObservationKey: key,
			Operator:       string(mc.Operator),
			ExpectedValue:  mc.ExpectedValue,
			ObservedValue:  mc.ObservedValue,
		}
		if translation.ClassifyClause(key) == translation.RoleGate {
			scope = append(scope, c)
		} else {
			reasoning = append(reasoning, c)
		}
	}
	if len(scope) > 0 {
		d.f("   Scope:\n")
		for _, c := range scope {
			d.f("     %s\n", translation.RenderClause(c, translation.GetDefaultFieldRegistry()))
		}
	}
	if len(reasoning) > 0 {
		d.f("   Reasoning:\n")
		for _, c := range reasoning {
			d.f("     %s\n", translation.RenderClause(c, translation.GetDefaultFieldRegistry()))
		}
	}
}

// writeFindingTriage renders the authored DEFECT / INFECTION / FAILURE
// chain — Andreas Zeller's failure-theory vocabulary applied to cloud
// misconfigurations. Iterates Finding.TriageEntries() so the
// presence-and-order policy stays on the type that owns the prose;
// renderers do not branch on each field individually.
func writeFindingTriage(d *drawer, f *remediation.Finding) {
	for _, entry := range f.TriageEntries() {
		d.f("   %s:\n", entry.Label)
		d.f("     %s\n", collapseWhitespace(entry.Text))
	}
}

// writeFindingObserved renders the property-path / observed-value pairs
// the predicate consulted during evaluation. Gated on the joint
// presence of authored triage AND a reasoning trace via
// HasObservableDiagnosis — preserving byte-identical output for
// unauthored controls.
func writeFindingObserved(d *drawer, f *remediation.Finding) {
	if !f.HasObservableDiagnosis() {
		return
	}
	d.f("   Observed:\n")
	for _, mc := range f.ReasoningTrace {
		d.f("     %s = %s\n", mc.ObservationKey, formatObservedValue(mc.ObservedValue))
	}
}

// writeFindingDelta renders the DELTA section — mechanically derived fix
// paths from the predicate and observed values. Gated on
// HasDeltaDiagnosis (triage AND delta).
func writeFindingDelta(d *drawer, f *remediation.Finding) {
	if !f.HasDeltaDiagnosis() {
		return
	}
	if len(f.Delta) == 1 {
		dp := f.Delta[0]
		d.f("   Delta:\n")
		d.f("     Change: %s\n", dp.PropertyLabel)
		d.f("     Current: %s\n", dp.CurrentValue)
		d.f("     Fix: %s\n", dp.FixAction)
	} else {
		d.f("   Delta (any ONE eliminates this finding):\n")
		for i, dp := range f.Delta {
			d.f("     %d. %s\n", i+1, dp.PropertyLabel)
			d.f("        Current: %s\n", dp.CurrentValue)
			d.f("        Fix: %s\n", dp.FixAction)
		}
	}
}

// collapseWhitespace normalizes multi-line YAML-folded prose (which keeps
// trailing newlines and single-space line joins) into a single clean
// line for text rendering.
func collapseWhitespace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// formatObservedValue renders a scalar or composite observation value
// for display alongside its property path. Strings are quoted; other
// types use Go default formatting.
func formatObservedValue(v any) string {
	if v == nil {
		return "<absent>"
	}
	switch t := v.(type) {
	case string:
		return "\"" + t + "\""
	default:
		return fmt.Sprint(t)
	}
}

func writeFindingRemediation(d *drawer, f *remediation.Finding) {
	if f.RemediationSpec.IsEmpty() {
		return
	}
	d.f("   Remediation:\n")
	if f.RemediationSpec.Description != "" {
		d.f("     %s\n", f.RemediationSpec.Description)
	}
	// Prefer the parameterized command from RemediationPlan when
	// available; fall back to the raw Action template. This matches
	// SARIF's fixes[] rendering and JSON's remediation_context.action
	// so the three output surfaces agree on which form the reader
	// sees. parameterizeCommand always populates RemediationPlan.Command
	// when the Action is non-empty (for prose-only controls it
	// equals Action by construction), so this branch is the common
	// path; the fallback covers enrichment flows that skip the
	// planner.
	if action := remediationAction(f); action != "" {
		d.f("     Action: %s\n", action)
	}
}

// remediationAction returns the action text to display, delegating
// to Finding.EffectiveRemediationCommand which encapsulates the
// (Plan.Command preferred over Spec.Action) fallback chain.
func remediationAction(f *remediation.Finding) string {
	return f.EffectiveRemediationCommand()
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
