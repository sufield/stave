// Package exemptlapse detects expired exemptions during assessment and
// produces EXEMPTION_LAPSED findings with severity bump for unreviewed
// risk acceptances. This converts exemption governance from manual
// tracking to engine-enforced policy.
package exemptlapse

import (
	"strings"
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

// FindingType classifies lapsed finding types.
type FindingType string

const (
	FindingTypeExemptionLapsed FindingType = "EXEMPTION_LAPSED"
)

// DaysSinceExpiry encapsulates the elapsed time in days since an exemption expired.
type DaysSinceExpiry int

// Int returns the raw integer number of days.
func (d DaysSinceExpiry) Int() int {
	return int(d)
}

// IsSeverityBumped reports whether the elapsed days exceed the severity bump threshold (30 days).
func (d DaysSinceExpiry) IsSeverityBumped() bool {
	return d > severityBumpThresholdDays
}

// Duration returns the elapsed time as a time.Duration.
func (d DaysSinceExpiry) Duration() time.Duration {
	return time.Duration(d) * 24 * time.Hour
}

// ExemptionID represents a unique exemption identifier composed of control, asset type, and asset ID.
type ExemptionID string

// String returns the raw string value of the exemption ID.
func (id ExemptionID) String() string {
	return string(id)
}

// IsEmpty reports whether the exemption ID is empty.
func (id ExemptionID) IsEmpty() bool {
	return strings.TrimSpace(string(id)) == ""
}

// ControlID returns the control ID portion of the exemption ID (before the first '@').
func (id ExemptionID) ControlID() string {
	parts := strings.Split(string(id), "@")
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

// AssetID returns the asset ID portion of the exemption ID (after the last '@').
func (id ExemptionID) AssetID() string {
	parts := strings.Split(string(id), "@")
	if len(parts) > 1 {
		return parts[len(parts)-1]
	}
	return ""
}

// NewExemptionID constructs an ExemptionID from control ID, asset type, and asset ID.
func NewExemptionID(ctlID kernel.ControlID, assetType kernel.AssetType, assetID asset.ID) ExemptionID {
	if assetType != "" {
		return ExemptionID(string(ctlID) + "@" + string(assetType) + "@" + string(assetID))
	}
	return ExemptionID(string(ctlID) + "@" + string(assetID))
}

// LapsedFinding represents an exemption that has expired.
type LapsedFinding struct {
	FindingType        FindingType      `json:"finding_type"`
	ControlID          kernel.ControlID `json:"control_id"`
	AssetID            asset.ID         `json:"asset_id"`
	Severity           policy.Severity  `json:"severity"`
	OriginalSeverity   policy.Severity  `json:"original_severity"`
	ExemptionID        ExemptionID      `json:"exemption_id"`
	GrantedAt          string           `json:"exemption_granted_at"`
	ExpiredAt          string           `json:"exemption_expired_at"`
	DaysSinceExpiry    DaysSinceExpiry  `json:"days_since_expiry"`
	SeverityBumpReason string           `json:"severity_bump_reason,omitempty"`
	CompensatingNote   string           `json:"compensating_note,omitempty"`
}

// LapsedFindings represents a collection of LapsedFinding entries with query methods.
type LapsedFindings []LapsedFinding

// Len returns the number of lapsed findings.
func (lf LapsedFindings) Len() int {
	return len(lf)
}

// BumpedCount returns the number of findings whose severity was bumped due to threshold expiry.
func (lf LapsedFindings) BumpedCount() int {
	count := 0
	for i := range lf {
		if lf[i].SeverityBumpReason != "" {
			count++
		}
	}
	return count
}

// BySeverity returns a subset of lapsed findings matching the given severity.
func (lf LapsedFindings) BySeverity(sev policy.Severity) LapsedFindings {
	var filtered LapsedFindings
	for i := range lf {
		if lf[i].Severity == sev {
			filtered = append(filtered, lf[i])
		}
	}
	return filtered
}

// Input configures the lapse detection.
type Input struct {
	Findings []evaluation.Finding
	EvalTime time.Time
}

// Detect scans suppressed findings for expired or invalid exemptions
// and produces LapsedFinding entries.
func Detect(in Input) LapsedFindings {
	evalTime := in.EvalTime
	if evalTime.IsZero() {
		evalTime = ports.RealClock{}.Now()
	}
	var lapsed LapsedFindings

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

		daysSince := DaysSinceExpiry(0)
		if !expiry.IsZero() {
			daysSince = DaysSinceExpiry(max(0, int(evalTime.Sub(expiry).Hours()/24)))
		}

		originalSev := f.ControlSeverity
		if !originalSev.IsSet() {
			originalSev = policy.SeverityMedium
		}
		effectiveSev := originalSev

		var bumpReason string
		if daysSince.IsSeverityBumped() {
			effectiveSev = originalSev.Bump(1)
			bumpReason = "Known risk allowed to expire unreviewed"
		}

		var compensatingNote string
		if f.Suppression.InvalidReason == "compensating_controls_failing" {
			compensatingNote = "Compensating control is failing"
		}

		exemptionID := NewExemptionID(f.ControlID, f.AssetType, f.AssetID)

		lf := LapsedFinding{
			FindingType:        FindingTypeExemptionLapsed,
			ControlID:          f.ControlID,
			AssetID:            f.AssetID,
			Severity:           effectiveSev,
			OriginalSeverity:   originalSev,
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
