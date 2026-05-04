package reporter

import (
	"fmt"
	"io"
	"strings"

	"github.com/sufield/stave/internal/core/compliance/compound"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/profile"
)

// TextReporter writes a human-readable text report.
type TextReporter struct{}

// stickyWriter captures the first I/O error and turns subsequent
// writes into no-ops. The text reporter emits dozens of Fprintf
// calls; checking each return inline would clutter the body and
// obscure the layout. The sticky pattern keeps the per-section
// helpers readable while still surfacing a real I/O failure
// (closed pipe, full disk) up to Write's caller.
type stickyWriter struct {
	w   io.Writer
	err error
}

func (s *stickyWriter) Write(p []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	n, err := s.w.Write(p)
	if err != nil {
		s.err = err
	}
	return n, err
}

// Write renders the report as formatted text.
func (TextReporter) Write(w io.Writer, report profile.Report, meta ReportMeta) error {
	sw := &stickyWriter{w: w}
	writeHeader(sw, report, meta)
	writeCompoundRisks(sw, report.CompoundFindings)
	writeFindingsBySeverity(sw, report.Results)
	writeAcknowledged(sw, report.Acknowledged)
	writeSummary(sw, report)
	return sw.err
}

func writeHeader(w io.Writer, report profile.Report, meta ReportMeta) {
	fmt.Fprintf(w, "═══ %s ═══\n", report.ProfileName)
	fmt.Fprintf(w, "Bucket:    %s\n", meta.BucketName)
	fmt.Fprintf(w, "Account:   %s\n", RedactAccountID(meta.AccountID))
	fmt.Fprintf(w, "Snapshot:  %s\n", meta.Timestamp)
	fmt.Fprintf(w, "Result:    %s\n\n", passLabel(report.Pass))
}

func writeCompoundRisks(w io.Writer, findings []compound.Finding) {
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

func writeFindingsBySeverity(w io.Writer, results []profile.Result) {
	for _, sev := range []policy.Severity{policy.SeverityCritical, policy.SeverityHigh, policy.SeverityMedium, policy.SeverityLow} {
		group := filterBySeverity(results, sev)
		if len(group) == 0 {
			continue
		}
		fmt.Fprintf(w, "── %s ──\n\n", sev)
		for _, r := range group {
			fmt.Fprintf(w, "  [%s] %s — %s\n", r.StatusLabel(), r.ControlID, r.Severity)
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
		fmt.Fprintf(w, "  [%s] %s — %s\n", ack.StatusLabel(), ack.ControlID, ack.Bucket)
		fmt.Fprintf(w, "  Rationale: %s\n", ack.Rationale)
		fmt.Fprintf(w, "  Acknowledged by: %s\n", ack.AcknowledgedBy)
		if !ack.IsValid() {
			fmt.Fprintf(w, "  Reason: %s\n", ack.ReasonDetail())
		}
		fmt.Fprintln(w)
	}
}

func writeSummary(w io.Writer, report profile.Report) {
	fmt.Fprintln(w, "── Summary ──")
	fmt.Fprintln(w)
	for _, sev := range []policy.Severity{policy.SeverityCritical, policy.SeverityHigh, policy.SeverityMedium, policy.SeverityLow} {
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

func filterBySeverity(results []profile.Result, sev policy.Severity) []profile.Result {
	var out []profile.Result
	for _, r := range results {
		if r.MatchesSeverity(sev) {
			out = append(out, r)
		}
	}
	return out
}

// String returns the full text report as a string.
func (t TextReporter) String(report profile.Report, meta ReportMeta) string {
	var b strings.Builder
	// Write to strings.Builder never returns an error.
	_ = t.Write(&b, report, meta)
	return b.String()
}

// RedactAccountID returns a partially redacted account ID showing only
// the last 4 digits: "123456789012" → "********9012".
func RedactAccountID(accountID string) string {
	if len(accountID) <= 4 {
		return accountID
	}
	redacted := make([]byte, len(accountID))
	for i := range redacted {
		redacted[i] = '*'
	}
	copy(redacted[len(redacted)-4:], accountID[len(accountID)-4:])
	return string(redacted)
}
