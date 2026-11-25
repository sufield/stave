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
	"strings"

	appcontracts "github.com/sufield/stave/internal/core/contracts"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/env"
	"github.com/sufield/stave/internal/platform/crypto"
)

// FindingWriter marshals findings as human-readable text.
type FindingWriter struct {
	Verbose              bool
	ShowAllIndeterminate bool
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
	if !result.HasFindings() {
		w.writeNoViolationsSummary(d)
		w.writeIndeterminate(d, enriched)
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
	w.writeIndeterminate(d, enriched)
	w.writeSkippedControls(d, &result)
	writeExemptedAssets(d, enriched)

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
	if !result.HasFindings() {
		w.writeNoViolationsSummary(d)
		w.writeIndeterminate(d, enriched)
		if d.err != nil {
			return nil, d.err
		}
		return buf.Bytes(), nil
	}

	w.writeConciseTable(d, enriched)
	w.writeIndeterminate(d, enriched)

	if result.HasChainFindings() {
		d.f("\nCompound Chains: %d\n", len(result.ChainFindings))
		for i := range result.ChainFindings {
			d.f("  [%s] %s\n", result.ChainFindings[i].Severity, result.ChainFindings[i].ChainID)
		}
	}
	if result.HasNearMissChains() {
		d.f("\nNear-Miss Chains: %d\n", len(result.NearMissChains))
		for i := range result.NearMissChains {
			nm := &result.NearMissChains[i]
			d.f("  [%s] %s — missing: %s\n", nm.Severity, nm.ChainID, nm.MissingControl)
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
	hasMITRE := false
	for i := range enriched.Findings {
		if extractMITRE(enriched.Findings[i].CorpusReference) != "" {
			hasMITRE = true
			break
		}
	}

	d.ln("Findings")
	d.ln("--------")
	if hasMITRE {
		d.f("  %-4s %-10s %-12s %-40s %s\n", "#", "Severity", "MITRE", "Control", "Asset")
	} else {
		d.f("  %-4s %-10s %-40s %s\n", "#", "Severity", "Control", "Asset")
	}
	for i := range enriched.Findings {
		f := &enriched.Findings[i]
		mitre := extractMITRE(f.CorpusReference)
		control := shortControlID(string(f.ControlID))
		assetName := shortAssetID(string(f.AssetID))
		if hasMITRE {
			d.f("  %-4d %-10s %-12s %-40s %s\n",
				i+1, f.ControlSeverity, mitre, control, assetName)
		} else {
			d.f("  %-4d %-10s %-40s %s\n",
				i+1, f.ControlSeverity, control, assetName)
		}
		if f.ControlName != "" {
			d.f("  %4s %s\n", "", f.ControlName)
		}
		if f.Defect != "" {
			d.f("  %4s Trigger: %s\n", "", f.Defect)
		}
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
		id = id[idx+1:]
	} else if idx := strings.LastIndex(id, ":"); idx >= 0 {
		id = id[idx+1:]
	}
	return stripControlChars(id)
}

func stripControlChars(s string) string {
	clean := make([]byte, 0, len(s))
	for i := range len(s) {
		b := s[i]
		if b >= 0x20 && b != 0x7f {
			clean = append(clean, b)
		}
	}
	if len(clean) == len(s) {
		return s
	}
	return string(clean)
}

func (w *FindingWriter) writeHeader(d *drawer, result *evaluation.ComplianceReport) {
	d.ln("Evaluation Results")
	d.ln("==================")
	d.f("\nRun: %s (max-unsafe: %s, snapshots: %d)\n",
		result.Run.EvalTime.Format("2006-01-02 15:04:05 UTC"),
		result.Run.MaxUnsafeDuration.String(),
		result.Run.Snapshots)
	w.writeAttestationStatus(d, result)
	d.f("\n")
	d.ln("Summary")
	d.ln("-------")
	d.f("  Assets evaluated:    %d\n", result.Summary.TotalAssets)
	d.f("  Attack surface:      %d\n", result.Summary.ExposedResources)
	d.f("  Violations:          %d\n", result.Summary.Violations)
	if result.Summary.HasIndeterminate() {
		d.f("  Indeterminate:       %d\n", result.Summary.Indeterminate)
	}
	if result.HasIssues() {
		d.f("  Issues (consolidated): %d\n", len(result.Issues))
	}
	d.f("\n")
}

func (w *FindingWriter) writeAttestationStatus(d *drawer, result *evaluation.ComplianceReport) {
	att := result.Metadata.Attestation
	if att == nil {
		return
	}
	switch att.Status {
	case evaluation.AttestationVerified:
		d.f("Attestation: VERIFIED (key: %s)\n", att.KeyFingerprint)
	case evaluation.AttestationFailed:
		d.f("Attestation: FAILED — DATA INTEGRITY COMPROMISED\n")
	case evaluation.AttestationUnsigned:
		d.f("Attestation: UNSIGNED\n")
	}
}

func (w *FindingWriter) writeNoViolationsSummary(d *drawer) {
	d.f("No violations found.\n")
	if !env.Demo.IsTrue() {
		d.f("\nNext step: run `stave apply` after remediation snapshots to confirm no regressions.\n")
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

	exploitableFindings, oneAwayFindings, reachableFindings := partitionByExploitability(enriched)

	num := 1
	num = w.writeExploitableSection(d, exploitableFindings, num)
	num = w.writeOneAwaySection(d, oneAwayFindings, num, len(exploitableFindings) > 0)
	_ = w.writeReachableSection(d, reachableFindings, num,
		len(exploitableFindings) > 0 || len(oneAwayFindings) > 0)
}

func (w *FindingWriter) writeExploitableSection(d *drawer, findings []remediation.Finding, num int) int {
	for i := range findings {
		w.writeChainMemberFinding(d, num, &findings[i])
		num++
	}
	return num
}

func (w *FindingWriter) writeOneAwaySection(d *drawer, findings []remediation.Finding, num int, needSep bool) int {
	if len(findings) == 0 {
		return num
	}
	if needSep {
		d.f("\n%s\n", strings.Repeat("─", 60))
	}
	for i := range findings {
		w.writeOneAwayFinding(d, num, &findings[i])
		num++
	}
	return num
}

func (w *FindingWriter) writeReachableSection(d *drawer, findings []remediation.Finding, num int, needSep bool) int {
	if len(findings) == 0 {
		return num
	}
	if needSep {
		d.f("\n%s\n", strings.Repeat("─", 60))
	}
	for i := range findings {
		w.writeIsolatedFinding(d, num, &findings[i], needSep)
		num++
	}
	return num
}

func partitionByExploitability(findings []remediation.Finding) (exploitable, oneAway, reachable []remediation.Finding) {
	for i := range findings {
		switch findings[i].Exploitability {
		case evaluation.ExploitabilityExploitable:
			exploitable = append(exploitable, findings[i])
		case evaluation.ExploitabilityOneAway:
			oneAway = append(oneAway, findings[i])
		default:
			reachable = append(reachable, findings[i])
		}
	}
	return
}

func (w *FindingWriter) writeSkippedControls(d *drawer, result *evaluation.ComplianceReport) {
	if !result.HasSkippedControls() {
		return
	}
	d.f("\nSkipped Controls: %d\n", len(result.SkippedControls))
	for _, s := range result.SkippedControls {
		d.f("  - %s: %s\n", s.ControlID, s.Reason)
	}
}

func writeExemptedAssets(d *drawer, enriched *appcontracts.EnrichedResult) {
	if !enriched.HasExemptedAssets() {
		return
	}
	d.f("\nExempted Assets: %d\n", len(enriched.ExemptedAssets))
	for _, s := range enriched.ExemptedAssets {
		d.f("  - %s: %s\n", s.ID, s.Reason)
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

// maxIndeterminateDisplay is the default cap on indeterminate findings
// shown in text output. Use --indeterminate-only to see all.
const maxIndeterminateDisplay = 3

// writeIndeterminate renders the indeterminate section — controls that
// could not be evaluated because required fields were absent from the
// observation snapshot. Text output caps display at maxIndeterminateDisplay;
// use --indeterminate-only to see the full list.
func (w *FindingWriter) writeIndeterminate(d *drawer, enriched *appcontracts.EnrichedResult) {
	if !enriched.HasIndeterminateFindings() {
		return
	}
	total := len(enriched.IndeterminateFindings)
	d.f("\nIndeterminate (%d) — cannot evaluate, data missing\n", total)
	d.ln(strings.Repeat("-", 50))
	limit := total
	if !w.ShowAllIndeterminate && limit > maxIndeterminateDisplay {
		limit = maxIndeterminateDisplay
	}
	for i := 0; i < limit; i++ {
		f := &enriched.IndeterminateFindings[i]
		missing := f.MissingFields()
		d.f("  %-10s %-40s %s\n",
			f.ControlSeverity,
			shortControlID(string(f.ControlID)),
			shortAssetID(string(f.AssetID)),
		)
		if len(missing) > 0 {
			d.f("             Missing: %s\n", strings.Join(missing, ", "))
		}
	}
	if limit < total {
		d.f("  ... and %d more (use --indeterminate-only to see all)\n", total-limit)
	}
	d.f("\n  Collect the missing fields to convert these to confirmed findings or passes.\n")
}
