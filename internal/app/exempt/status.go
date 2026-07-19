package exempt

import (
	"time"
)

// StatusReport holds the exemption health report.
type StatusReport struct {
	GeneratedAt    string         `json:"generated_at"`
	TotalActive    int            `json:"total_active"`
	ExpiringDays30 int            `json:"expiring_within_30d"`
	ExpiringDays60 int            `json:"expiring_within_60d"`
	AlreadyExpired int            `json:"expired_not_revoked"`
	Resolved       int            `json:"resolved_finding_active_exemption"`
	ExpiringItems  []ExpiryItem   `json:"expiring,omitempty"`
	ExpiredItems   []ExpiryItem   `json:"expired,omitempty"`
	ResolvedItems  []ResolvedItem `json:"resolved,omitempty"`
}

// ExpiryItem describes an expiring or expired exemption.
type ExpiryItem struct {
	ControlID     string `json:"control_id"`
	AssetID       string `json:"asset_id"`
	ExpiryDate    string `json:"expiry_date"`
	DaysRemaining int    `json:"days_remaining"`
	Reason        string `json:"reason"`
}

// ResolvedItem describes an exemption where the finding no longer exists.
type ResolvedItem struct {
	ControlID      string `json:"control_id"`
	AssetID        string `json:"asset_id"`
	GrantedDate    string `json:"granted_date"`
	Recommendation string `json:"recommendation"`
}

// ComputeStatus analyzes exemption health.
func ComputeStatus(file *AcceptanceFile, now time.Time, activeFindings map[string]struct{}) *StatusReport {
	report := &StatusReport{
		GeneratedAt: now.Format(time.RFC3339),
	}

	for i := range file.Acknowledgments {
		ack := &file.Acknowledgments[i]
		if !ack.IsActive() {
			continue
		}
		report.TotalActive++

		daysRemaining, ok := ack.DaysRemaining(now)
		if ok {
			switch ack.ExpiryClassification(now) {
			case "expired":
				report.AlreadyExpired++
				report.ExpiredItems = append(report.ExpiredItems, ExpiryItem{
					ControlID:     ack.ControlID,
					AssetID:       ack.AssetID,
					ExpiryDate:    ack.ExpiryDate,
					DaysRemaining: daysRemaining,
					Reason:        ack.Reason,
				})
			case "expiring_soon":
				report.ExpiringDays30++
				report.ExpiringDays60++
				report.ExpiringItems = append(report.ExpiringItems, ExpiryItem{
					ControlID:     ack.ControlID,
					AssetID:       ack.AssetID,
					ExpiryDate:    ack.ExpiryDate,
					DaysRemaining: daysRemaining,
					Reason:        ack.Reason,
				})
			case "expiring_60d":
				report.ExpiringDays60++
				report.ExpiringItems = append(report.ExpiringItems, ExpiryItem{
					ControlID:     ack.ControlID,
					AssetID:       ack.AssetID,
					ExpiryDate:    ack.ExpiryDate,
					DaysRemaining: daysRemaining,
					Reason:        ack.Reason,
				})
			}
		}

		key := ack.ControlID + "@" + ack.AssetID
		_, active := activeFindings[key]
		if activeFindings != nil && !active {
			report.Resolved++
			report.ResolvedItems = append(report.ResolvedItems, ResolvedItem{
				ControlID:      ack.ControlID,
				AssetID:        ack.AssetID,
				GrantedDate:    ack.AcknowledgedDate,
				Recommendation: "revoke exemption — finding no longer active",
			})
		}
	}

	return report
}
