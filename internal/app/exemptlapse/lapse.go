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
	EvalTime             time.Time
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
			daysSince = max(0, int(in.EvalTime.Sub(expiry).Hours()/24))
		}

		// Findings without a recorded severity (zero value) are treated
		// as Medium for governance purposes — an unreviewed risk
		// acceptance with unknown severity should still surface, and
		// "medium" is the historical default this lapse path emitted.
		originalSev := af.Severity
		if !originalSev.IsSet() {
			originalSev = policy.SeverityMedium
		}
		effectiveSev := originalSev

		var bumpReason string
		if daysSince > severityBumpThresholdDays {
			effectiveSev = originalSev.Bump(1)
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
			Severity:           effectiveSev.BucketName(),
			OriginalSeverity:   originalSev.BucketName(),
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
