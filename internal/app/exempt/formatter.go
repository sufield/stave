package exempt

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// WriteList renders an acceptance file as either a structured table
// (default) or JSON. The listType filters which sections appear:
// "all" shows acknowledgments + exceptions + exemptions; specific
// types restrict to one section. showExpired includes revoked /
// expired acknowledgments in the table view.
//
// JSON output ignores listType and showExpired — JSON consumers
// filter their own view from the full document. Mixing wire-format
// and view-filtering on the same flag would diverge between
// human-readable and machine-readable output.
func WriteList(w io.Writer, f *AcceptanceFile, format, listType string, showExpired bool) error {
	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(f)
	}

	acks, exceptions, exemptions := f.ActiveCount()
	fmt.Fprintf(w, "Risk Acceptances: %d acknowledgments, %d exceptions, %d exemptions\n\n",
		acks, exceptions, exemptions)

	if listType == "all" || listType == "acknowledgment" {
		for i := range f.Acknowledgments {
			a := &f.Acknowledgments[i]
			if !showExpired && (a.IsRevoked() || a.IsExpired()) {
				continue
			}
			fmt.Fprintf(w, "  [ACK]  %-40s  expires %s  %s  %s\n",
				a.ID, a.ExpiryDate, a.Approver, strings.ToUpper(a.Status))
		}
	}
	if listType == "all" || listType == "exception" {
		for _, e := range f.Exceptions {
			exp := "never"
			if e.ExpiryDate != "" {
				exp = e.ExpiryDate
			}
			fmt.Fprintf(w, "  [EXC]  %s@%s  expires %s\n", e.ControlID, e.AssetID, exp)
		}
	}
	if listType == "all" || listType == "exemption" {
		for _, e := range f.Exemptions {
			fmt.Fprintf(w, "  [EXM]  %s  %s\n", e.AssetPattern, e.Reason)
		}
	}
	return nil
}

// WriteHistory renders the full acknowledgment audit trail in
// human-readable form. Used by `stave exempt history` for ops
// review of past risk-acceptance decisions.
func WriteHistory(w io.Writer, entries []AcknowledgmentEntry) {
	fmt.Fprintln(w, "ACKNOWLEDGMENT AUDIT TRAIL")
	fmt.Fprintln(w, strings.Repeat("-", 70))
	for i := range entries {
		a := &entries[i]
		fmt.Fprintf(w, "\n  %s  [%s]\n", a.ID, strings.ToUpper(a.Status))
		fmt.Fprintf(w, "    Control:   %s\n", a.ControlID)
		fmt.Fprintf(w, "    Asset:     %s\n", a.AssetID)
		fmt.Fprintf(w, "    Approver:  %s\n", a.Approver)
		fmt.Fprintf(w, "    Expires:   %s\n", a.ExpiryDate)
		fmt.Fprintf(w, "    Rationale: %s\n", a.Reason)
		if len(a.AuditTrail) > 0 {
			fmt.Fprintln(w, "    Events:")
			for j := range a.AuditTrail {
				e := &a.AuditTrail[j]
				fmt.Fprintf(w, "      %s  %s  %s", e.Timestamp, e.Event, e.Actor)
				if e.Note != "" {
					fmt.Fprintf(w, "  (%s)", e.Note)
				}
				fmt.Fprintln(w)
			}
		}
	}
}
