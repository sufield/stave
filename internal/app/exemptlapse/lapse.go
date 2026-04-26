// Package exemptlapse detects expired exemptions during assessment and
// produces EXEMPTION_LAPSED findings with severity bump for unreviewed
// risk acceptances. This converts exemption governance from manual
// tracking to engine-enforced policy.
package exemptlapse

import (
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// severityBumpThresholdDays is how long past expiry before severity
// is bumped one level. A risk acceptance that expires without review
// indicates a governance process failure — the longer it goes
// unreviewed, the higher the organizational risk.
const severityBumpThresholdDays = 30

// LapsedFinding represents an exemption that has expired.
type LapsedFinding struct {
	FindingType        string           `json:"finding_type"`
	ControlID          kernel.ControlID `json:"control_id"`
	AssetID            asset.ID         `json:"asset_id"`
	Severity           string           `json:"severity"`
	OriginalSeverity   string           `json:"original_severity"`
	ExemptionID        string           `json:"exemption_id"`
	GrantedAt          string           `json:"exemption_granted_at"`
	ExpiredAt          string           `json:"exemption_expired_at"`
	DaysSinceExpiry    int              `json:"days_since_expiry"`
	SeverityBumpReason string           `json:"severity_bump_reason,omitempty"`
	CompensatingNote   string           `json:"compensating_note,omitempty"`
}

// Input configures the lapse detection.
type Input struct {
	AcknowledgedFindings []policy.AcknowledgedFinding
	Now                  time.Time
}

// Detect scans acknowledged findings for expired exemptions and
// produces LapsedFinding entries.
func Detect(in Input) []LapsedFinding {
	var lapsed []LapsedFinding

	for i := range in.AcknowledgedFindings {
		af := &in.AcknowledgedFindings[i]

		if af.Valid {
			continue
		}

		if af.InvalidReason != "expired" && af.InvalidReason != "compensating_controls_failing" {
			continue
		}

		expiry, err := time.Parse("2006-01-02", af.ExpiryDate)
		if err != nil && af.InvalidReason == "expired" {
			continue
		}

		daysSince := 0
		if !expiry.IsZero() {
			daysSince = max(0, int(in.Now.Sub(expiry).Hours()/24))
		}

		originalSev := severityFromFinding(af)
		effectiveSev := originalSev

		var bumpReason string
		if daysSince > severityBumpThresholdDays {
			effectiveSev = bumpSeverity(originalSev)
			bumpReason = "Known risk allowed to expire unreviewed"
		}

		var compensatingNote string
		if af.InvalidReason == "compensating_controls_failing" {
			compensatingNote = "Compensating control is failing"
		}

		lf := LapsedFinding{
			FindingType:        "EXEMPTION_LAPSED",
			ControlID:          af.ControlID,
			AssetID:            af.AssetID,
			Severity:           effectiveSev,
			OriginalSeverity:   originalSev,
			ExemptionID:        string(af.ControlID) + "@" + string(af.AssetID),
			GrantedAt:          af.AcknowledgedDate,
			ExpiredAt:          af.ExpiryDate,
			DaysSinceExpiry:    daysSince,
			SeverityBumpReason: bumpReason,
			CompensatingNote:   compensatingNote,
		}
		lapsed = append(lapsed, lf)
	}

	return lapsed
}

func severityFromFinding(af *policy.AcknowledgedFinding) string {
	switch af.Severity {
	case policy.SeverityCritical:
		return "critical"
	case policy.SeverityHigh:
		return "high"
	case policy.SeverityMedium:
		return "medium"
	case policy.SeverityLow:
		return "low"
	case policy.SeverityInfo:
		return "info"
	default:
		return "medium"
	}
}

// bumpSeverity increases severity by one level.
func bumpSeverity(sev string) string {
	switch sev {
	case "low":
		return "medium"
	case "medium":
		return "high"
	case "high":
		return "critical"
	default:
		return sev
	}
}
