// Package exemptlapse detects expired exemptions during assessment and
// produces EXEMPTION_LAPSED findings with severity bump for unreviewed
// risk acceptances. This converts exemption governance from manual
// tracking to engine-enforced policy.
package exemptlapse

import (
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
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
	Findings []evaluation.Finding
	EvalTime time.Time
}

// Detect scans suppressed findings for expired or invalid exemptions
// and produces LapsedFinding entries.
func Detect(in Input) []LapsedFinding {
	evalTime := in.EvalTime
	if evalTime.IsZero() {
		evalTime = ports.RealClock{}.Now()
	}
	var lapsed []LapsedFinding

	for i := range in.Findings {
		f := &in.Findings[i]

		if f.Status != evaluation.FindingSuppressed {
			continue
		}
		if f.Suppression == nil || f.Suppression.Valid {
			continue
		}
		if f.Suppression.InvalidReason != "expired" && f.Suppression.InvalidReason != "compensating_controls_failing" {
			continue
		}

		expiry, err := time.Parse("2006-01-02", f.Suppression.ExpiryDate)
		if err != nil && f.Suppression.InvalidReason == "expired" {
			continue
		}

		daysSince := 0
		if !expiry.IsZero() {
			daysSince = max(0, int(evalTime.Sub(expiry).Hours()/24))
		}

		originalSev := f.ControlSeverity
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
		if f.Suppression.InvalidReason == "compensating_controls_failing" {
			compensatingNote = "Compensating control is failing"
		}

		exemptionID := string(f.ControlID) + "@" + string(f.AssetID)
		if f.AssetType != "" {
			exemptionID = string(f.ControlID) + "@" + string(f.AssetType) + "@" + string(f.AssetID)
		}

		lf := LapsedFinding{
			FindingType:        "EXEMPTION_LAPSED",
			ControlID:          f.ControlID,
			AssetID:            f.AssetID,
			Severity:           effectiveSev.BucketName(),
			OriginalSeverity:   originalSev.BucketName(),
			ExemptionID:        exemptionID,
			GrantedAt:          f.Suppression.AcknowledgedDate,
			ExpiredAt:          f.Suppression.ExpiryDate,
			DaysSinceExpiry:    daysSince,
			SeverityBumpReason: bumpReason,
			CompensatingNote:   compensatingNote,
		}
		lapsed = append(lapsed, lf)
	}

	return lapsed
}
