package dto

import (
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/findings"
	"github.com/sufield/stave/internal/core/kernel"
)

// FindingDTO mirrors remediation.Finding for JSON output.
type FindingDTO struct {
	FindingID          string                    `json:"finding_id"`
	ControlID          kernel.ControlID          `json:"control_id"`
	ControlName        string                    `json:"control_name"`
	ControlDescription string                    `json:"control_description"`
	AssetID            asset.ID                  `json:"asset_id"`
	AssetType          kernel.AssetType          `json:"asset_type"`
	AssetVendor        kernel.Vendor             `json:"asset_vendor"`
	Source             *SourceRefDTO             `json:"source,omitempty"`
	Evidence           EvidenceDTO               `json:"evidence"`
	ControlSeverity    string                    `json:"control_severity,omitempty"`
	ControlCompliance  map[string]string         `json:"control_compliance,omitempty"`
	ControlCCMV4       []string                  `json:"control_compliance_ccm_v4,omitempty"`
	Exposure           *ExposureDTO              `json:"exposure,omitempty"`
	PostureDrift       *PostureDriftDTO          `json:"posture_drift,omitempty"`
	Remediation        RemediationSpecDTO        `json:"remediation"`
	RemediationPlan    *RemediationPlanDTO       `json:"fix_plan,omitempty"`
	ChainMembership    []ChainMembershipEntryDTO `json:"chain_membership,omitempty"`
	SLADeadlineHours   *float64                  `json:"sla_deadline_hours,omitempty"`
	// SLABreached is a *bool so an SLA-bearing finding that is within
	// its deadline serialises an explicit "sla_breached": false, while
	// a finding with no SLA at all omits the key entirely (nil pointer).
	// A plain bool with omitempty would erase the within-SLA false
	// signal, collapsing "has SLA, not breached" into "no SLA".
	SLABreached          *bool                    `json:"sla_breached,omitempty"`
	SLAOverdueHours      *float64                 `json:"sla_overdue_hours,omitempty"`
	SLAEscalatedSeverity string                   `json:"sla_escalated_severity,omitempty"`
	SLAPolicySource      string                   `json:"sla_policy_source,omitempty"`
	ExposureScore        float64                  `json:"exposure_score,omitempty"`
	ScoreBreakdown       *findings.ScoreBreakdown `json:"score_breakdown,omitempty"`
	ReasoningTrace       []MatchedClauseDTO       `json:"reasoning_trace,omitempty"`
	RemediationContext   *RemediationContextDTO   `json:"remediation_context,omitempty"`
	Alternatives         []AlternativeDTO         `json:"alternatives,omitempty"`
	Classification       string                   `json:"classification,omitempty"`
	ScopeTags            []string                 `json:"scope_tags,omitempty"`
	Defect               string                   `json:"defect,omitempty"`
	Infection            string                   `json:"infection,omitempty"`
	Failure              string                   `json:"failure,omitempty"`
	Archetype            string                   `json:"archetype,omitempty"`
	ControlScope         string                   `json:"control_scope,omitempty"`
	CorpusReference      string                   `json:"corpus_reference,omitempty"`
	Delta                []DeltaPathDTO           `json:"delta,omitempty"`
	// ContributingFactIDs links a CEL finding to the SIR fact_ids
	// that describe the same asset. Each id matches the `fact_id`
	// emitted by `stave export-sir --format jsonl` and the
	// `;; fact_id:` comment in `stave export-sir --format smt2`.
	// Populated when applycore could build the SIR projection
	// post-evaluation; empty (omitted from JSON) when SIR build
	// failed or the field was never stamped on the source finding.
	ContributingFactIDs []string `json:"contributing_fact_ids,omitempty"`
}

// DeltaPathDTO represents one independent fix path in JSON output.
type DeltaPathDTO struct {
	PropertyLabel string `json:"property_label"`
	PropertyPath  string `json:"property_path"`
	CurrentValue  string `json:"current_value"`
	FixAction     string `json:"fix_action"`
}

// AlternativeDTO mirrors controldef.Alternative for JSON output.
// Each entry maps this finding's control to a check in an alternative
// detection tool. Tool is an opaque string identifier.
type AlternativeDTO struct {
	Tool     string `json:"tool"`
	CheckID  string `json:"check_id"`
	Coverage string `json:"coverage"`
	Note     string `json:"note,omitempty"`
}

// RemediationContextDTO packages asset identity, violation reasoning,
// structured changes, and the parameterized command in one shape a
// downstream consumer (AI prompt, CI/CD, ticket system) can feed
// directly into a fix-generation template. See
// docs/product/metrics.md § Metric 4.
type RemediationContextDTO struct {
	Asset     RemediationAssetDTO     `json:"asset"`
	Violation RemediationViolationDTO `json:"violation"`
	Changes   []PropertyChangeDTO     `json:"changes,omitempty"`
	// Action carries the remediation text — parameterized CLI when
	// the underlying control declares a templated command, or prose
	// when the control's action is descriptive. The field name
	// matches the control YAML's `action:` field; content may be
	// executable (CLI) or advisory (prose) depending on catalog
	// authoring. See docs/product/metrics.md § Metric 4.
	Action string `json:"action,omitempty"`
}

// RemediationAssetDTO carries the asset identity a downstream consumer
// needs to act on this finding.
type RemediationAssetDTO struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Vendor string `json:"vendor,omitempty"`
	ARN    string `json:"arn,omitempty"`
	Region string `json:"region,omitempty"`
}

// RemediationViolationDTO summarizes the violation: what fired, why.
type RemediationViolationDTO struct {
	ControlID   string                    `json:"control_id"`
	ControlName string                    `json:"control_name"`
	Severity    string                    `json:"severity,omitempty"`
	Reasoning   []RemediationReasoningDTO `json:"reasoning,omitempty"`
}

// RemediationReasoningDTO renders one matched clause in both the
// structured form (observation_key, observed_value) and the
// plain-English clause the text writer would show.
type RemediationReasoningDTO struct {
	Clause         string `json:"clause"`
	ObservationKey string `json:"observation_key"`
	ObservedValue  any    `json:"observed_value,omitempty"`
}

// PropertyChangeDTO mirrors controldef.PropertyChange for the JSON
// output of the remediation_context block.
type PropertyChangeDTO struct {
	Path                string `json:"path"`
	CurrentValue        string `json:"current_value"`
	RequiredValue       string `json:"required_value,omitempty"`
	RequiredValuePrompt string `json:"required_value_prompt,omitempty"`
	HasSafeDefault      bool   `json:"has_safe_default"`
	Description         string `json:"description,omitempty"`
}

// MatchedClauseDTO mirrors evaluation.MatchedClause.
type MatchedClauseDTO struct {
	PredicateExpr  string `json:"predicate_expr"`
	ObservationKey string `json:"observation_key"`
	Operator       string `json:"operator"`
	ExpectedValue  any    `json:"expected_value,omitempty"`
	ObservedValue  any    `json:"observed_value,omitempty"`
}

// ChainMembershipEntryDTO mirrors evaluation.ChainMembershipEntry.
type ChainMembershipEntryDTO struct {
	ChainID       string   `json:"chain_id"`
	ChainSeverity string   `json:"chain_severity"`
	StageSpan     []string `json:"stage_span"`
	Narrative     string   `json:"narrative"`
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
	RecurrenceThreshold   int                   `json:"recurrence_threshold,omitempty"`
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

// AtRiskItemDTO mirrors findings.ThresholdItem.
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
