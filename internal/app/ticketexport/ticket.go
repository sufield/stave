// Package ticketexport generates canonical ticketing schema from findings
// with stable ticket IDs and severity-to-priority mapping.
package ticketexport

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

// Priority represents the ticketing priority classification.
type Priority string

const (
	PriorityP1 Priority = "P1"
	PriorityP2 Priority = "P2"
	PriorityP3 Priority = "P3"
	PriorityP4 Priority = "P4"
)

// Ticket is the canonical ticketing schema for a finding.
type Ticket struct {
	TicketID    string           `json:"ticket_id"`
	Title       string           `json:"title"`
	Severity    policy.Severity  `json:"severity"`
	Priority    Priority         `json:"priority"`
	DueDate     string           `json:"due_date,omitempty"`
	Description string           `json:"description"`
	Labels      []string         `json:"labels"`
	AssetID     asset.ID         `json:"asset_id"`
	ControlID   kernel.ControlID `json:"control_id"`
	Team        string           `json:"team,omitempty"`
	Status      string           `json:"status"`
	DwellDays   float64          `json:"dwell_days"`
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

// StableTicketID computes a deterministic ticket ID from control_id, asset_id, and optional asset_type.
func StableTicketID(controlID, assetID string, assetType ...string) string {
	h := sha256.New()
	astType := ""
	if len(assetType) > 0 {
		astType = assetType[0]
	}
	fmt.Fprintf(h, "%d:%s:%d:%s:%d:%s", len(controlID), controlID, len(assetID), assetID, len(astType), astType)
	return "TKT-" + hex.EncodeToString(h.Sum(nil))[:12]
}

// SeverityToPriority maps severity levels to priority codes.
func SeverityToPriority(severity string) Priority {
	switch severity {
	case "critical":
		return PriorityP1
	case "high":
		return PriorityP2
	case "medium":
		return PriorityP3
	default:
		return PriorityP4
	}
}

func fromFinding(f *remediation.Finding) Ticket {
	ctlID := string(f.ControlID)
	astID := string(f.AssetID)
	astType := string(f.AssetType)
	sev := f.SeverityLabel()
	dwellDays := f.DwellDays()

	labels := []string{"security", sev}
	if f.AssetType != "" {
		labels = append(labels, astType)
	}

	desc := f.ControlDescription
	if f.RemediationSpec.Action != "" {
		desc = fmt.Sprintf("%s\n\nRemediation: %s", desc, f.RemediationSpec.Action)
	}

	team := f.OwnerTeamName

	return Ticket{
		TicketID:    StableTicketID(ctlID, astID, astType),
		Title:       fmt.Sprintf("[%s] %s - %s", sev, f.ControlName, astID),
		Severity:    f.ControlSeverity,
		Priority:    SeverityToPriority(sev),
		Description: desc,
		Labels:      labels,
		AssetID:     f.AssetID,
		ControlID:   f.ControlID,
		Team:        team,
		Status:      "open",
		DwellDays:   dwellDays,
	}
}
