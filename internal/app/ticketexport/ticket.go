// Package ticketexport generates canonical ticketing schema from findings
// with stable ticket IDs and severity-to-priority mapping.
package ticketexport

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/sufield/stave/internal/core/evaluation/remediation"
)

// Ticket is the canonical ticketing schema for a finding.
type Ticket struct {
	TicketID    string   `json:"ticket_id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Priority    string   `json:"priority"`
	DueDate     string   `json:"due_date,omitempty"`
	Description string   `json:"description"`
	Labels      []string `json:"labels"`
	AssetID     string   `json:"asset_id"`
	ControlID   string   `json:"control_id"`
	Team        string   `json:"team,omitempty"`
	Status      string   `json:"status"`
	DwellDays   float64  `json:"dwell_days"`
}

// Generate creates tickets from findings with stable IDs and priority mapping.
func Generate(findings []remediation.Finding) []Ticket {
	tickets := make([]Ticket, 0, len(findings))
	for i := range findings {
		f := &findings[i]
		tickets = append(tickets, fromFinding(f))
	}
	return tickets
}

// StableTicketID computes a deterministic ticket ID from control_id + asset_id.
func StableTicketID(controlID, assetID string) string {
	h := sha256.New()
	h.Write([]byte(controlID))
	h.Write([]byte("+"))
	h.Write([]byte(assetID))
	return "TKT-" + hex.EncodeToString(h.Sum(nil))[:12]
}

// SeverityToPriority maps severity levels to priority codes.
func SeverityToPriority(severity string) string {
	switch severity {
	case "critical":
		return "P1"
	case "high":
		return "P2"
	case "medium":
		return "P3"
	case "low":
		return "P4"
	default:
		return "P4"
	}
}

func fromFinding(f *remediation.Finding) Ticket {
	ctlID := string(f.ControlID)
	astID := string(f.AssetID)
	sev := f.SeverityLabel()
	dwellDays := f.Evidence.UnsafeDurationHours / 24

	labels := []string{"security", sev}
	if f.AssetType != "" {
		labels = append(labels, string(f.AssetType))
	}

	desc := f.ControlDescription
	if f.RemediationSpec.Action != "" {
		desc = fmt.Sprintf("%s\n\nRemediation: %s", desc, f.RemediationSpec.Action)
	}

	team := f.OwnerTeamName

	return Ticket{
		TicketID:    StableTicketID(ctlID, astID),
		Title:       fmt.Sprintf("[%s] %s - %s", sev, f.ControlName, astID),
		Severity:    sev,
		Priority:    SeverityToPriority(sev),
		Description: desc,
		Labels:      labels,
		AssetID:     astID,
		ControlID:   ctlID,
		Team:        team,
		Status:      "open",
		DwellDays:   dwellDays,
	}
}
