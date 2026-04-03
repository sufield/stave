package reporter

import (
	"fmt"
	"io"
	"strings"

	"github.com/sufield/stave/internal/core/compliance"
	"github.com/sufield/stave/internal/core/compliance/compound"
	"github.com/sufield/stave/internal/profile"
)

// TextReporter writes a human-readable text report.
type TextReporter struct{}

// Write renders the report as formatted text.
func (TextReporter) Write(w io.Writer, report profile.ProfileReport, meta ReportMeta) error {
	writeHeader(w, report, meta)
	writeCompoundRisks(w, report.CompoundFindings)
	writeFindingsBySeverity(w, report.Results)
	writeAcknowledged(w, report.Acknowledged)
	writeSummary(w, report)
	return nil
}

func writeHeader(w io.Writer, report profile.ProfileReport, meta ReportMeta) {
	fmt.Fprintf(w, "═══ %s ═══\n", report.ProfileName)
	fmt.Fprintf(w, "Bucket:    %s\n", meta.BucketName)
	fmt.Fprintf(w, "Account:   %s\n", RedactAccountID(meta.AccountID))
	fmt.Fprintf(w, "Snapshot:  %s\n", meta.Timestamp)
	fmt.Fprintf(w, "Result:    %s\n\n", passLabel(report.Pass))
}

func writeCompoundRisks(w io.Writer, findings []compound.CompoundFinding) {
	if len(findings) == 0 {
		return
	}
	fmt.Fprintln(w, "── COMPOUND RISKS ──")
	fmt.Fprintln(w)
	for _, cf := range findings {
		fmt.Fprintf(w, "  [%s] %s (triggers: %s)\n", cf.Severity, cf.ID, strings.Join(cf.TriggerIDs, ", "))
		fmt.Fprintf(w, "  %s\n\n", cf.Message)
	}
}

func writeFindingsBySeverity(w io.Writer, results []profile.ProfileResult) {
	for _, sev := range []compliance.Severity{compliance.Critical, compliance.High, compliance.Medium, compliance.Low} {
		group := filterBySeverity(results, sev)
		if len(group) == 0 {
			continue
		}
		fmt.Fprintf(w, "── %s ──\n\n", sev)
		for _, r := range group {
			status := "PASS"
			if !r.Pass {
				status = "FAIL"
			}
			fmt.Fprintf(w, "  [%s] %s — %s\n", status, r.ControlID, r.Severity)
			if r.ComplianceRef != "" {
				fmt.Fprintf(w, "  Compliance: %s", r.ComplianceRef)
				if r.Rationale != "" {
					fmt.Fprintf(w, " — %s", r.Rationale)
				}
				fmt.Fprintln(w)
			}
			if r.Finding != "" {
				fmt.Fprintf(w, "  Finding: %s\n", r.Finding)
			}
			if r.Remediation != "" {
				fmt.Fprintf(w, "  Remediation: %s\n", r.Remediation)
			}
			fmt.Fprintln(w)
		}
	}
}

func writeAcknowledged(w io.Writer, acknowledged []profile.AcknowledgedEntry) {
	if len(acknowledged) == 0 {
		return
	}
	fmt.Fprintln(w, "── Acknowledged Exceptions ──")
	fmt.Fprintln(w)
	for _, ack := range acknowledged {
		status := "VALID"
		if !ack.Valid {
			status = "INVALID"
		}
		fmt.Fprintf(w, "  [%s] %s — %s\n", status, ack.ControlID, ack.Bucket)
		fmt.Fprintf(w, "  Rationale: %s\n", ack.Rationale)
		fmt.Fprintf(w, "  Acknowledged by: %s\n", ack.AcknowledgedBy)
		if !ack.Valid {
			fmt.Fprintf(w, "  Reason: %s\n", ack.InvalidReason)
		}
		fmt.Fprintln(w)
	}
}

func writeSummary(w io.Writer, report profile.ProfileReport) {
	fmt.Fprintln(w, "── Summary ──")
	fmt.Fprintln(w)
	for _, sev := range []compliance.Severity{compliance.Critical, compliance.High, compliance.Medium, compliance.Low} {
		total := report.Counts[sev]
		failed := report.FailCounts[sev]
		if total == 0 {
			continue
		}
		fmt.Fprintf(w, "  %s: %d/%d passed\n", sev, total-failed, total)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Overall: %s\n\n", passLabel(report.Pass))
	fmt.Fprintf(w, "%s\n", disclaimer)
}

func passLabel(pass bool) string {
	if pass {
		return "PASS"
	}
	return "FAIL"
}

func filterBySeverity(results []profile.ProfileResult, sev compliance.Severity) []profile.ProfileResult {
	var out []profile.ProfileResult
	for _, r := range results {
		if r.Severity == sev {
			out = append(out, r)
		}
	}
	return out
}

// String returns the full text report as a string.
func (t TextReporter) String(report profile.ProfileReport, meta ReportMeta) string {
	var b strings.Builder
	_ = t.Write(&b, report, meta)
	return b.String()
}
