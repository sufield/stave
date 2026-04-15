package evaluation

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"slices"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// Finding represents a detected control violation.
// A Finding is purely factual: evidence + classification, no advice.
type Finding struct {
	FindingID          string                   `json:"finding_id"`
	ControlID          kernel.ControlID         `json:"control_id"`
	ControlName        string                   `json:"control_name"`
	ControlDescription string                   `json:"control_description"`
	AssetID            asset.ID                 `json:"asset_id"`
	AssetType          kernel.AssetType         `json:"asset_type"`
	AssetVendor        kernel.Vendor            `json:"asset_vendor"`
	Source             *asset.SourceRef         `json:"source,omitempty"`
	Evidence           Evidence                 `json:"evidence"`
	ControlSeverity    policy.Severity          `json:"control_severity,omitempty"`
	ControlCompliance  policy.ComplianceMapping `json:"control_compliance,omitempty"`
	Exposure           *policy.Exposure         `json:"exposure,omitempty"`
	PostureDrift       *PostureDrift            `json:"posture_drift,omitempty"`
	ControlRemediation *policy.RemediationSpec  `json:"-"`

	// ChainMembership is non-empty when this finding is a member
	// of one or more chains that are currently firing.
	ChainMembership []ChainMembershipEntry `json:"chain_membership,omitempty"`

	// SLA fields — populated when an SLA deadline applies to this finding.
	SLADeadlineHours     *float64 `json:"sla_deadline_hours,omitempty"`
	SLABreached          bool     `json:"sla_breached,omitempty"`
	SLAOverdueHours      *float64 `json:"sla_overdue_hours,omitempty"`
	SLAEscalatedSeverity string   `json:"sla_escalated_severity,omitempty"`
	SLAPolicySource      string   `json:"sla_policy_source,omitempty"`

	// Owner routing — populated when a team manifest is loaded.
	OwnerTeamID     string `json:"owner_team_id,omitempty"`
	OwnerTeamName   string `json:"owner_team_name,omitempty"`
	OwnerContact    string `json:"owner_contact,omitempty"`
	OwnerResolution string `json:"owner_resolution_path,omitempty"`
}

// ChainMembershipEntry records that a finding contributed to a fired chain.
type ChainMembershipEntry struct {
	// ChainID is the chain definition ID (e.g. "data_exfiltration_path").
	ChainID string `json:"chain_id"`

	// ChainSeverity is the compound severity of the chain.
	ChainSeverity string `json:"chain_severity"`

	// StageSpan is the attack stage progression of the chain,
	// sorted by kill chain order.
	StageSpan []string `json:"stage_span"`

	// Narrative is the chain's human-readable description.
	Narrative string `json:"narrative"`
}

// SortFindings sorts findings deterministically.
func SortFindings(fs []Finding) {
	slices.SortFunc(fs, func(a, b Finding) int {
		return cmp.Or(
			cmp.Compare(a.ControlID, b.ControlID),
			cmp.Compare(a.AssetID, b.AssetID),
			cmp.Compare(a.Evidence.TemporalRisk, b.Evidence.TemporalRisk),
			cmp.Compare(a.ControlName, b.ControlName),
			cmp.Compare(a.AssetType, b.AssetType),
		)
	})
}

// StableFindingID computes a deterministic fingerprint for a (control, asset) pair.
// Same inputs always produce the same ID, enabling cross-run finding correlation.
func StableFindingID(ctlID kernel.ControlID, astID asset.ID) string {
	h := sha256.New()
	h.Write([]byte("finding:"))
	h.Write([]byte(ctlID))
	h.Write([]byte(":"))
	h.Write([]byte(astID))
	return "sha256:" + hex.EncodeToString(h.Sum(nil))[:16]
}

// NewFindingFromMetadata creates a Finding pre-populated with control metadata.
func NewFindingFromMetadata(m policy.ControlMetadata) Finding {
	return Finding{
		ControlID:          m.ID,
		ControlName:        m.Name,
		ControlDescription: m.Description,
		ControlSeverity:    m.Severity,
		ControlCompliance:  m.Compliance,
		ControlRemediation: m.Remediation,
		Exposure:           m.Exposure,
	}
}

// ExceptedFinding records a finding that was excepted, with audit trail.
type ExceptedFinding struct {
	ControlID kernel.ControlID  `json:"control_id"`
	AssetID   asset.ID          `json:"asset_id"`
	Reason    string            `json:"reason"`
	Expires   policy.ExpiryDate `json:"expires"`
}
