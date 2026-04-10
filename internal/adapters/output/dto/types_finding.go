package dto

import (
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

// FindingDTO mirrors remediation.Finding for JSON output.
type FindingDTO struct {
	ControlID          kernel.ControlID    `json:"control_id"`
	ControlName        string              `json:"control_name"`
	ControlDescription string              `json:"control_description"`
	AssetID            asset.ID            `json:"asset_id"`
	AssetType          kernel.AssetType    `json:"asset_type"`
	AssetVendor        kernel.Vendor       `json:"asset_vendor"`
	Source             *SourceRefDTO       `json:"source,omitempty"`
	Evidence           EvidenceDTO         `json:"evidence"`
	ControlSeverity    string              `json:"control_severity,omitempty"`
	ControlCompliance  map[string]string   `json:"control_compliance,omitempty"`
	Exposure           *ExposureDTO        `json:"exposure,omitempty"`
	PostureDrift       *PostureDriftDTO    `json:"posture_drift,omitempty"`
	Remediation        RemediationSpecDTO  `json:"remediation"`
	RemediationPlan    *RemediationPlanDTO `json:"fix_plan,omitempty"`
}

// SourceRefDTO mirrors asset.SourceRef.
type SourceRefDTO struct {
	File string `json:"file"`
	Line int    `json:"line"`
}

// EvidenceDTO mirrors evaluation.Evidence.
type EvidenceDTO struct {
	FirstUnsafeAt         time.Time             `json:"first_unsafe_at,omitzero"`
	LastSeenUnsafeAt      time.Time             `json:"last_seen_unsafe_at,omitzero"`
	UnsafeDurationHours   float64               `json:"unsafe_duration_hours,omitempty"`
	ThresholdHours        float64               `json:"threshold_hours,omitempty"`
	ExposureWindowCount   int                   `json:"exposure_window_count,omitempty"`
	WindowDays            int                   `json:"window_days,omitempty"`
	RecurrenceLimit       int                   `json:"recurrence_limit,omitempty"`
	FirstExposureWindowAt time.Time             `json:"first_exposure_window_at,omitzero"`
	LastExposureWindowAt  time.Time             `json:"last_exposure_window_at,omitzero"`
	Misconfigurations     []MisconfigurationDTO `json:"misconfigurations,omitempty"`
	RootCauses            []string              `json:"root_causes,omitempty"`
	SourceEvidence        *SourceEvidenceDTO    `json:"source_evidence,omitempty"`
	TemporalRisk          string                `json:"temporal_risk,omitempty"`
}

// MisconfigurationDTO mirrors policy.Misconfiguration.
type MisconfigurationDTO struct {
	Property    string `json:"property"`
	ActualValue any    `json:"actual_value"`
	Operator    string `json:"operator"`
	UnsafeValue any    `json:"unsafe_value,omitempty"`
}

// SourceEvidenceDTO mirrors evaluation.SourceEvidence.
type SourceEvidenceDTO struct {
	IdentityStatements []string `json:"identity_statements,omitempty"`
	ResourceGrantees   []string `json:"resource_grantees,omitempty"`
}

// PostureDriftDTO mirrors evaluation.PostureDrift.
type PostureDriftDTO struct {
	Pattern             evaluation.DriftPattern `json:"pattern"`
	ExposureWindowCount int                     `json:"exposure_window_count"`
}

// ExposureDTO mirrors policy.Exposure.
type ExposureDTO struct {
	Type           string `json:"type"`
	PrincipalScope string `json:"principal_scope"`
}

// RemediationSpecDTO mirrors policy.RemediationSpec.
type RemediationSpecDTO struct {
	Description string `json:"description"`
	Action      string `json:"action"`
	Example     string `json:"example,omitempty"`
}

// ExceptedFindingDTO mirrors evaluation.ExceptedFinding.
type ExceptedFindingDTO struct {
	ControlID kernel.ControlID `json:"control_id"`
	AssetID   asset.ID         `json:"asset_id"`
	Reason    string           `json:"reason"`
	Expires   string           `json:"expires,omitempty"`
}

// SkippedControlDTO mirrors evaluation.SkippedControl.
type SkippedControlDTO struct {
	ControlID   kernel.ControlID `json:"control_id"`
	ControlName string           `json:"control_name"`
	Reason      string           `json:"reason"`
}

// ExemptedAssetDTO mirrors asset.ExemptedAsset.
type ExemptedAssetDTO struct {
	AssetID asset.ID `json:"asset_id"`
	Pattern string   `json:"matched_pattern"`
	Reason  string   `json:"reason"`
}

// RowDTO mirrors evaluation.ResourceCheck.
type RowDTO struct {
	ControlID    kernel.ControlID           `json:"control_id"`
	AssetID      asset.ID                   `json:"asset_id"`
	AssetType    kernel.AssetType           `json:"asset_type"`
	Domain       kernel.AssetDomain         `json:"asset_domain"`
	Verdict      evaluation.Verdict         `json:"verdict"`
	Confidence   evaluation.ConfidenceLevel `json:"confidence"`
	Evidence     *EvidenceDTO               `json:"evidence,omitempty"`
	TemporalRisk string                     `json:"temporal_risk,omitempty"`
	Reason       string                     `json:"reason,omitempty"`
}

// AtRiskItemDTO mirrors risk.ThresholdItem.
type AtRiskItemDTO struct {
	ControlID      kernel.ControlID `json:"control_id"`
	AssetID        asset.ID         `json:"asset_id"`
	AssetType      kernel.AssetType `json:"asset_type"`
	Status         string           `json:"status"`
	DueAt          time.Time        `json:"due_at"`
	RemainingHours float64          `json:"remaining_hours"`
	FirstUnsafeAt  time.Time        `json:"first_unsafe_at"`
	ThresholdHours float64          `json:"threshold_hours"`
}
