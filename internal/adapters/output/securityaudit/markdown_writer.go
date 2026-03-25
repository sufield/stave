package securityaudit

import (
	"fmt"
	"strings"
	"time"

	domain "github.com/sufield/stave/pkg/alpha/domain/securityaudit"
)

// MarshalMarkdownReport renders the security-audit report as markdown.
func MarshalMarkdownReport(report domain.Report) ([]byte, error) {
	var b strings.Builder
	b.Grow(5 * 1024)
	b.WriteString("# Stave Security Audit Report\n\n")
	renderHeader(&b, report)
	renderSummaryTable(&b, report.Summary)

	b.WriteString("## Findings\n\n")
	if len(report.Findings) == 0 {
		b.WriteString("No findings in selected severities.\n\n")
	} else {
		renderFindingsTable(&b, report.Findings)
		renderFindingDetails(&b, report.Findings)
	}
	renderEvidenceIndex(&b, report.EvidenceIndex)
	renderControlCoverage(&b, report.Controls)

	return []byte(b.String()), nil
}

func writeBullet(b *strings.Builder, label string, value any) {
	fmt.Fprintf(b, "- %s: `%s`\n", label, value)
}

func writeOptionalField(b *strings.Builder, label, value string) {
	if strings.TrimSpace(value) != "" {
		fmt.Fprintf(b, "- %s: %s\n", label, value)
	}
}

func renderHeader(b *strings.Builder, report domain.Report) {
	writeBullet(b, "Generated", report.GeneratedAt.Format(time.RFC3339))
	writeBullet(b, "Tool Version", report.StaveVersion)
	writeBullet(b, "Schema", report.SchemaVersion)
	writeBullet(b, "Fail Threshold", report.Summary.FailOn)
	writeBullet(b, "Vulnerability Evidence Source", report.Summary.VulnSourceUsed)
	writeBullet(b, "Evidence Freshness", report.Summary.EvidenceFreshness)
	b.WriteString("\n")
}

func renderSummaryTable(b *strings.Builder, summary domain.Summary) {
	b.WriteString("## Summary\n\n")
	b.WriteString("| Metric | Value |\n")
	b.WriteString("| :--- | ---: |\n")
	fmt.Fprintf(b, "| Total checks | %d |\n", summary.Total)
	fmt.Fprintf(b, "| Pass | %d |\n", summary.Pass)
	fmt.Fprintf(b, "| Warn | %d |\n", summary.Warn)
	fmt.Fprintf(b, "| Fail | %d |\n", summary.Fail)
	fmt.Fprintf(b, "| Gated findings | %d |\n", summary.GatedFindingCount)
	fmt.Fprintf(b, "| Gate triggered | `%t` |\n", summary.Gated)
	b.WriteString("\n")
}

func renderFindingsTable(b *strings.Builder, findings []domain.Finding) {
	b.WriteString("| Check ID | Pillar | Status | Severity | Title |\n")
	b.WriteString("| :--- | :--- | :---: | :---: | :--- |\n")
	for _, finding := range findings {
		fmt.Fprintf(
			b,
			"| `%s` | `%s` | `%s` | `%s` | %s |\n",
			finding.ID,
			finding.Pillar,
			finding.Status,
			finding.Severity,
			escapeMarkdownPipe(finding.Title),
		)
	}
	b.WriteString("\n")
}

func renderFindingDetails(b *strings.Builder, findings []domain.Finding) {
	for _, finding := range findings {
		fmt.Fprintf(b, "### `%s` — %s\n\n", finding.ID, finding.Title)
		writeBullet(b, "Pillar", finding.Pillar)
		writeBullet(b, "Status", finding.Status)
		writeBullet(b, "Severity", finding.Severity)
		writeOptionalField(b, "Details", finding.Details)
		writeOptionalField(b, "Auditor Hint", finding.AuditorHint)
		writeOptionalField(b, "Recommendation", finding.Recommendation)
		if len(finding.ControlRefs) > 0 {
			b.WriteString("- Controls:\n")
			for _, control := range finding.ControlRefs {
				fmt.Fprintf(
					b,
					"  - `%s` `%s`: %s\n",
					control.Framework,
					control.ControlID,
					control.Rationale,
				)
			}
		}
		if len(finding.EvidenceRefs) > 0 {
			fmt.Fprintf(b, "- Evidence Refs: `%s`\n", strings.Join(finding.EvidenceRefs, "`, `"))
		}
		b.WriteString("\n")
	}
}

func renderEvidenceIndex(b *strings.Builder, evidenceIndex []domain.EvidenceRef) {
	if len(evidenceIndex) == 0 {
		return
	}
	b.WriteString("## Evidence Index\n\n")
	b.WriteString("| ID | Path | SHA-256 |\n")
	b.WriteString("| :--- | :--- | :--- |\n")
	for _, evidence := range evidenceIndex {
		fmt.Fprintf(b, "| `%s` | `%s` | `%s` |\n", evidence.ID, evidence.Path, evidence.SHA256)
	}
	b.WriteString("\n")
}

func renderControlCoverage(b *strings.Builder, controls []domain.ControlRef) {
	if len(controls) == 0 {
		return
	}
	b.WriteString("## Control Coverage\n\n")
	b.WriteString("| Framework | Control ID | Rationale |\n")
	b.WriteString("| :--- | :--- | :--- |\n")
	for _, control := range controls {
		fmt.Fprintf(
			b,
			"| `%s` | `%s` | %s |\n",
			control.Framework,
			control.ControlID,
			escapeMarkdownPipe(control.Rationale),
		)
	}
}

func escapeMarkdownPipe(in string) string {
	return strings.ReplaceAll(strings.TrimSpace(in), "|", "\\|")
}
