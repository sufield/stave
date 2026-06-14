// Package text provides text-based output functionality for evaluation results.
// It handles formatting and writing of findings as human-readable text.
//
// TDA in adapters: this writer queries domain predicates
// (HasAlternatives, TemporalRiskMessage, PrimaryChain*, IsOverdue,
// ...) to decide which sections to render and what phrasing to use.
// That is acceptable Tell-Don't-Ask: the renderer asks the domain
// "is X true?" and picks a representation. It is NOT acceptable for
// the renderer to reproduce domain logic inline (e.g. composing a
// chain narrative from raw chain membership fields, or deciding SLA
// breach from raw deadline math) — those decisions belong on
// Finding so a single edit updates every output adapter at once.
package text

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/translation"
	"github.com/sufield/stave/internal/env"
	"github.com/sufield/stave/internal/platform/crypto"
)

// FindingWriter marshals findings as human-readable text.
type FindingWriter struct {
	Verbose bool
}

var _ appcontracts.FindingMarshaler = (*FindingWriter)(nil)

// MarshalFindings transforms enriched findings into human-readable text bytes
// without performing I/O.
//
// Returns an error when enriched is nil rather than panicking on
// the .Result access. Mirrors the same nil-guard added to the SARIF
// and JSON marshallers.
func (w *FindingWriter) MarshalFindings(enriched *appcontracts.EnrichedResult) ([]byte, error) {
	if enriched == nil {
		return nil, errors.New("text: nil EnrichedResult")
	}
	if w.Verbose {
		return w.marshalVerbose(enriched)
	}
	return w.marshalConcise(enriched)
}

func (w *FindingWriter) marshalVerbose(enriched *appcontracts.EnrichedResult) ([]byte, error) {
	var buf bytes.Buffer
	d := &drawer{w: &buf}
	result := enriched.Result

	w.writeHeader(d, &result)
	if len(result.Findings) == 0 {
		w.writeNoViolationsSummary(d)
		w.writeCoveragePosture(d, enriched.CoveragePosture)
		if d.err != nil {
			return nil, d.err
		}
		return buf.Bytes(), nil
	}

	remFindings := toRemediationFindings(enriched.Findings)
	w.writeIssues(d, &result)
	w.writeViolationsFromEnriched(d, &result, remFindings)
	w.writeChainFindings(d, &result)
	w.writeAttackStageSummary(d, &result)
	w.writeTopExposures(d, &result)
	w.writeFrameworkReadiness(d, &result)
	w.writeRemediationGroups(d, remFindings)
	w.writeSkippedControls(d, result.SkippedControls)
	writeExemptedAssets(d, enriched.ExemptedAssets)
	w.writeExceptedFindings(d, result.ExceptedFindings)
	w.writeCoveragePosture(d, enriched.CoveragePosture)
	if !env.Demo.IsTrue() {
		d.f("\nNext step: run `stave diagnose --controls <dir> --observations <dir>` for root-cause guidance.\n")
	}

	if d.err != nil {
		return nil, d.err
	}
	return buf.Bytes(), nil
}

func (w *FindingWriter) marshalConcise(enriched *appcontracts.EnrichedResult) ([]byte, error) {
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

	w.writeConciseTable(d, enriched)

	if len(result.ChainFindings) > 0 {
		d.f("\nCompound Chains: %d\n", len(result.ChainFindings))
		for i := range result.ChainFindings {
			d.f("  [%s] %s\n", result.ChainFindings[i].Severity, result.ChainFindings[i].ChainID)
		}
	}

	if !env.Demo.IsTrue() {
		d.f("\nRun with --verbose for full evidence, reasoning, and remediation.\n")
	}

	if d.err != nil {
		return nil, d.err
	}
	return buf.Bytes(), nil
}

func (w *FindingWriter) writeConciseTable(d *drawer, enriched *appcontracts.EnrichedResult) {
	d.ln("Findings")
	d.ln("--------")
	d.f("  %-4s %-10s %-12s %-40s %s\n", "#", "Severity", "MITRE", "Control", "Asset")
	for i := range enriched.Findings {
		f := &enriched.Findings[i]
		mitre := extractMITRE(f.CorpusReference)
		control := shortControlID(string(f.ControlID))
		assetName := shortAssetID(string(f.AssetID))
		d.f("  %-4d %-10s %-12s %-40s %s\n",
			i+1,
			f.ControlSeverity,
			mitre,
			control,
			assetName,
		)
	}
}

func extractMITRE(ref string) string {
	if strings.HasPrefix(ref, "MITRE:") {
		return ref[len("MITRE:"):]
	}
	return ""
}

func shortControlID(id string) string {
	// Strip the CTL.<domain>. prefix if present, keep the rest.
	// CTL.IAM.ESCALATE.CREATEACCESSKEY.001 → ESCALATE.CREATEACCESSKEY.001
	// CTL.IAM.POLICY.ADMIN.001 → POLICY.ADMIN.001
	// CTL.S3.PUBLIC.READ.001 → PUBLIC.READ.001
	if strings.HasPrefix(id, "CTL.") {
		if idx := strings.IndexByte(id[4:], '.'); idx >= 0 {
			if strings.IndexByte(id[4+idx+1:], '.') >= 0 {
				return id[4+idx+1:]
			}
		}
	}
	return id
}

func shortAssetID(id string) string {
	if idx := strings.LastIndex(id, "/"); idx >= 0 {
		return id[idx+1:]
	}
	if idx := strings.LastIndex(id, ":"); idx >= 0 {
		return id[idx+1:]
	}
	return id
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
	d.f("  Violations:          %d\n", result.Summary.Violations)
	if len(result.Issues) > 0 {
		d.f("  Issues (consolidated): %d\n", len(result.Issues))
	}
	d.f("\n")
}

func (w *FindingWriter) writeNoViolationsSummary(d *drawer) {
	d.f("No violations found.\n")
	if !env.Demo.IsTrue() {
		d.f("\nNext step: run `stave verify` after remediation snapshots to confirm no regressions.\n")
	}
}

// writeViolationsFromEnriched renders violation output from pre-enriched findings.
// Chain-member findings are promoted to the top with [ATTACK PATH] prefix.
func (w *FindingWriter) writeViolationsFromEnriched(d *drawer, result *evaluation.ComplianceReport, enriched []remediation.Finding) {
	d.ln("Violations")
	d.ln("----------")
	w.writeViolationDomainSummary(d, result.Checks)

	if d.err != nil {
		return
	}

	// Partition into chain-member and isolated findings via the
	// finding's own predicate so the renderer stops asking about
	// the slice length and asks the type instead.
	var chainFindings, isolatedFindings []remediation.Finding
	for i := range enriched {
		if enriched[i].IsChainMember() {
			chainFindings = append(chainFindings, enriched[i])
		} else {
			isolatedFindings = append(isolatedFindings, enriched[i])
		}
	}

	num := 1
	if len(chainFindings) > 0 {
		for i := range chainFindings {
			f := &chainFindings[i]
			w.writeChainMemberFinding(d, num, f)
			num++
		}
		if len(isolatedFindings) > 0 {
			d.f("\n%s\n", strings.Repeat("\u2500", 60))
		}
	}
	showIsolatedLabel := len(chainFindings) > 0
	for i := range isolatedFindings {
		f := &isolatedFindings[i]
		w.writeIsolatedFinding(d, num, f, showIsolatedLabel)
		num++
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
	for i := range excepted {
		s := &excepted[i]
		d.f("  - %s on %s: %s", s.ControlID, s.AssetID, s.Reason)
		if s.HasExpiry() {
			d.f(" (expires %s)", s.Expires)
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
	for _, stage := range []string{
		"initial_access", "execution", "credential_access", "persistence",
		"collection", "exfiltration", "detection_evasion", "resilience",
	} {
		status, ok := result.AttackStageSummary[kernel.AttackStage(stage)]
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
