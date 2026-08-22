package evaluation

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/findings"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
)

// MatchedClause records one predicate leaf clause and the observed
// value that triggered (or was considered in) the fire.
type MatchedClause struct {
	PredicateExpr  string                `json:"predicate_expr"`
	ObservationKey kernel.ObservationKey `json:"observation_key"`
	Operator       predicate.Operator    `json:"operator"`
	ExpectedValue  any                   `json:"expected_value,omitempty"`
	ObservedValue  any                   `json:"observed_value,omitempty"`
}

// ReachabilityContext carries IAM reachability data for a finding.
type ReachabilityContext struct {
	TotalReachablePrincipals   int                 `json:"total_reachable_principals"`
	PrivilegedPrincipalCount   int                 `json:"privileged_principal_count"`
	HighestPrivilegePrincipal  kernel.PrincipalRef `json:"highest_privilege_principal,omitempty"`
	ExternalPrincipalReachable bool                `json:"external_principal_reachable,omitempty"`
	BlastRadiusScore           kernel.BlastRadius  `json:"blast_radius_score"`
}

// SharedRoleContext carries the sharing count and peer list for
// findings on shared-role controls.
type SharedRoleContext struct {
	RoleARN      string     `json:"role_arn"`
	SharingCount int        `json:"sharing_count"`
	PeerAssetIDs []asset.ID `json:"peer_asset_ids,omitempty"`
}

// FindingStatus classifies a finding's lifecycle state.
type FindingStatus string

const (
	// FindingActive means the finding is a current violation.
	FindingActive FindingStatus = "ACTIVE"
	// FindingSuppressed means the finding was excepted or acknowledged.
	FindingSuppressed FindingStatus = "SUPPRESSED"
)

// Suppression records why a finding was suppressed (excepted or acknowledged).
type Suppression struct {
	Kind             string            `json:"kind"`
	Reason           string            `json:"reason,omitempty"`
	Expires          policy.ExpiryDate `json:"expires"`
	AcknowledgedBy   string            `json:"acknowledged_by,omitempty"`
	AcknowledgedDate string            `json:"acknowledged_date,omitempty"`
	ExpiryDate       string            `json:"expiry_date,omitempty"`
	Rationale        string            `json:"rationale,omitempty"`
	Valid            bool              `json:"valid"`
	InvalidReason    string            `json:"invalid_reason,omitempty"`
}

// Finding represents a detected control violation.
// A Finding is purely factual: evidence + classification, no advice.
type Finding struct {
	FindingID          kernel.FindingID         `json:"finding_id"`
	ControlID          kernel.ControlID         `json:"control_id"`
	ControlName        string                   `json:"control_name"`
	ControlDescription string                   `json:"control_description"`
	AssetID            asset.ID                 `json:"asset_id"`
	AssetType          kernel.AssetType         `json:"asset_type"`
	AssetVendor        kernel.Vendor            `json:"asset_vendor"`
	ObservedAt         time.Time                `json:"observed_at,omitzero"`
	Source             *asset.SourceRef         `json:"source,omitempty"`
	Evidence           Evidence                 `json:"evidence"`
	ControlSeverity    policy.Severity          `json:"control_severity,omitempty"`
	ControlCompliance  policy.ComplianceMapping `json:"control_compliance,omitempty"`
	ControlCCMV4       []string                 `json:"control_compliance_ccm_v4,omitempty"`
	Exposure           *policy.Exposure         `json:"exposure,omitempty"`
	PostureDrift       *PostureDrift            `json:"posture_drift,omitempty"`
	ControlRemediation *policy.RemediationSpec  `json:"-"`
	Alternatives       []policy.Alternative     `json:"alternatives,omitempty"`
	Classification     policy.Classification    `json:"classification,omitempty"`
	ScopeTags          []kernel.ScopeTag        `json:"scope_tags,omitempty"`

	// ChainMembership is non-empty when this finding is a member
	// of one or more chains that are currently firing.
	ChainMembership []ChainMembershipEntry `json:"chain_membership,omitempty"`

	// Exploitability classifies this finding's position in the attack
	// graph: exploitable (chain firing), one_away (one control short),
	// or reachable (no chain participation).
	Exploitability Exploitability `json:"exploitability,omitempty"`

	// NearMissChains is non-empty when this finding participates in
	// chains that are exactly one control short of firing.
	NearMissChains []NearMissEntry `json:"near_miss_chains,omitempty"`

	// DecidingLayer identifies which policy layer caused this finding.
	// Derived from the reasoning trace property paths.
	DecidingLayer DecidingLayer `json:"deciding_layer,omitempty"`

	// SLA fields — populated when an SLA deadline applies to this
	// finding. Private: only AnnotateSLA mutates them. External
	// readers go through the accessor methods (HasSLA, IsOverdue,
	// SLADeadlineValue, OverdueHours, SLAContribution, IsAnyBreach,
	// IsCriticalSLABreach, SLAEscalatedSeverityValue,
	// SLAPolicySourceLabel, SLADeadlinePtr, SLAOverduePtr,
	// SLABreachedFlag); JSON readers go through MarshalJSON /
	// UnmarshalJSON which expose the original sla_* tags via a
	// shadow struct. The Go visibility decision is therefore
	// decoupled from the wire-format shape.
	slaDeadlineHours     *float64
	slaBreached          bool
	slaOverdueHours      *float64
	slaEscalatedSeverity policy.Severity
	slaPolicySource      kernel.SLAPolicySource

	// Lifecycle deadline fields — populated when a control has a
	// sunset/eol deadline. Private: only AnnotateLifecycleDeadline
	// mutates them.
	lifecycleDeadline          string
	lifecycleDaysRemaining     *int
	lifecycleEscalatedSeverity policy.Severity

	// Owner routing — populated when a team manifest is loaded.
	OwnerTeamID     kernel.TeamID `json:"owner_team_id,omitempty"`
	OwnerTeamName   string        `json:"owner_team_name,omitempty"`
	OwnerContact    string        `json:"owner_contact,omitempty"`
	OwnerResolution string        `json:"owner_resolution_path,omitempty"`

	// Reachability — populated when IAM data is in the snapshot.
	Reachability *ReachabilityContext `json:"reachability,omitempty"`

	// SharedRoleContext — populated by the shared role index enrichment
	// for controls that detect shared execution roles (e.g. CTL.LAMBDA.ROLE.SHARED.001).
	SharedRoleContext *SharedRoleContext `json:"shared_role,omitempty"`

	// Confidence qualifies the certainty of this finding's verdict.
	Confidence      ConfidenceLevel `json:"confidence,omitempty"`
	FreshnessReason string          `json:"freshness_reason,omitempty"`

	// ExposureScore is the priority score used to order findings.
	ExposureScore kernel.ExposureScore `json:"exposure_score,omitempty"`

	// ScoreBreakdown decomposes ExposureScore into the factors that produced it.
	ScoreBreakdown *findings.ScoreBreakdown `json:"score_breakdown,omitempty"`

	// ReasoningTrace lists the predicate leaf clauses that the engine
	// evaluated to produce this finding, each paired with the observed
	// value from the snapshot.
	ReasoningTrace []MatchedClause `json:"reasoning_trace,omitempty"`

	// Defect / Infection / Failure carry the authored triage chain.
	Defect    string `json:"defect,omitempty"`
	Infection string `json:"infection,omitempty"`
	Failure   string `json:"failure,omitempty"`

	Archetype       kernel.ArchetypeID `json:"archetype,omitempty"`
	Scope           string             `json:"control_scope,omitempty"`
	CorpusReference string             `json:"corpus_reference,omitempty"`

	// Delta is the mechanically-derived set of fix paths.
	Delta []policy.DeltaPath `json:"delta,omitempty"`

	// ContributingFactIDs lists the SIR fact_ids for the asset.
	ContributingFactIDs []string `json:"contributing_fact_ids,omitempty"`

	// Status classifies the finding lifecycle: ACTIVE or SUPPRESSED.
	Status FindingStatus `json:"status,omitempty"`

	// Suppression records why a suppressed finding was exempted.
	Suppression *Suppression `json:"suppression,omitempty"`
}

// findingShadow is the wire-format projection used by Finding's
// custom MarshalJSON / UnmarshalJSON. It exposes the SLA fields
// under their original sla_* JSON tags so external consumers see
// the identical wire format regardless of whether the Go fields
// are exported.
type findingShadow struct {
	*findingAlias
	SLADeadlineHours     *float64               `json:"sla_deadline_hours,omitempty"`
	SLABreached          bool                   `json:"sla_breached,omitempty"`
	SLAOverdueHours      *float64               `json:"sla_overdue_hours,omitempty"`
	SLAEscalatedSeverity policy.Severity        `json:"sla_escalated_severity,omitempty"`
	SLAPolicySource      kernel.SLAPolicySource `json:"sla_policy_source,omitempty"`

	LifecycleDeadline          string          `json:"lifecycle_deadline,omitempty"`
	LifecycleDaysRemaining     *int            `json:"lifecycle_days_remaining,omitempty"`
	LifecycleEscalatedSeverity policy.Severity `json:"lifecycle_escalated_severity,omitempty"`
}

type findingAlias Finding

func (f *Finding) MarshalJSON() ([]byte, error) {
	if f == nil {
		return []byte("null"), nil
	}
	alias := findingAlias(*f)
	return json.Marshal(findingShadow{
		findingAlias:         &alias,
		SLADeadlineHours:     f.slaDeadlineHours,
		SLABreached:          f.slaBreached,
		SLAOverdueHours:      f.slaOverdueHours,
		SLAEscalatedSeverity: f.slaEscalatedSeverity,
		SLAPolicySource:      f.slaPolicySource,

		LifecycleDeadline:          f.lifecycleDeadline,
		LifecycleDaysRemaining:     f.lifecycleDaysRemaining,
		LifecycleEscalatedSeverity: f.lifecycleEscalatedSeverity,
	})
}

func (f *Finding) UnmarshalJSON(data []byte) error {
	alias := (*findingAlias)(f)
	var shadow findingShadow
	shadow.findingAlias = alias
	if err := json.Unmarshal(data, &shadow); err != nil {
		return err
	}
	f.slaDeadlineHours = shadow.SLADeadlineHours
	f.slaBreached = shadow.SLABreached
	f.slaOverdueHours = shadow.SLAOverdueHours
	f.slaEscalatedSeverity = shadow.SLAEscalatedSeverity
	f.slaPolicySource = shadow.SLAPolicySource
	f.lifecycleDeadline = shadow.LifecycleDeadline
	f.lifecycleDaysRemaining = shadow.LifecycleDaysRemaining
	f.lifecycleEscalatedSeverity = shadow.LifecycleEscalatedSeverity
	return nil
}

// IsIndeterminate reports whether this finding depends on at least one
// absent field whose absence genuinely signals a data gap rather than
// a confirmed detection.
//
// Exceptions that do NOT count as data gaps:
//   - op=missing / op=present: designed to fire on absent fields.
//   - op=any_match / any_identity_match / any_in_field: resolve from
//     the identity collection, not the property map — absence in the
//     property map is structural, not a data gap.
//   - Disjunction siblings: when an `any` (OR) block has at least one
//     branch with confirmed data (or op=missing), absent fields in
//     other branches are irrelevant — only one branch needs to match.
func (f *Finding) IsIndeterminate() bool {
	// First pass: find disjunction groups that have at least one
	// confirmed branch (present field or op=missing).
	confirmed := map[int]bool{}
	for _, mc := range f.Evidence.Misconfigurations {
		if mc.DisjunctionID > 0 && (!mc.FieldAbsent || mc.Operator == predicate.OpMissing) {
			confirmed[mc.DisjunctionID] = true
		}
	}

	for _, mc := range f.Evidence.Misconfigurations {
		if !mc.FieldAbsent {
			continue
		}
		if isAbsenceOperator(mc.Operator) {
			continue
		}
		if mc.DisjunctionID > 0 && confirmed[mc.DisjunctionID] {
			continue
		}
		return true
	}
	return false
}

func isAbsenceOperator(op predicate.Operator) bool {
	switch op {
	case predicate.OpMissing, predicate.OpPresent,
		predicate.OpAnyMatch, predicate.OpAnyIdentityMatch, predicate.OpAnyInField:
		return true
	}
	return false
}

// MissingFields returns the field paths that were absent from the asset
// properties when this finding was produced. Only meaningful when
// IsIndeterminate returns true.
func (f *Finding) MissingFields() []string {
	confirmed := map[int]bool{}
	for _, mc := range f.Evidence.Misconfigurations {
		if mc.DisjunctionID > 0 && (!mc.FieldAbsent || mc.Operator == predicate.OpMissing) {
			confirmed[mc.DisjunctionID] = true
		}
	}

	var fields []string
	for _, mc := range f.Evidence.Misconfigurations {
		if !mc.FieldAbsent || isAbsenceOperator(mc.Operator) {
			continue
		}
		if mc.DisjunctionID > 0 && confirmed[mc.DisjunctionID] {
			continue
		}
		fields = append(fields, mc.DisplayProperty())
	}
	return fields
}

// SortFindings sorts findings by actionable priority:
// ExposureScore descending, with alphabetical tiebreaker.
func SortFindings(fs []Finding) {
	slices.SortFunc(fs, func(a, b Finding) int {
		return cmp.Or(
			cmp.Compare(b.ExposureScore, a.ExposureScore),
			cmp.Compare(a.ControlID, b.ControlID),
			cmp.Compare(a.AssetID, b.AssetID),
			cmp.Compare(a.FindingID, b.FindingID),
			cmp.Compare(a.ControlName, b.ControlName),
			cmp.Compare(a.AssetType, b.AssetType),
		)
	})
}

// StableFindingID computes a deterministic fingerprint for a (control, asset) pair.
func StableFindingID(ctlID kernel.ControlID, astID asset.ID) kernel.FindingID {
	h := sha256.New()
	h.Write([]byte("finding:"))
	fmt.Fprintf(h, "%d:%s:%d:%s", len(ctlID), ctlID, len(astID), astID)
	return kernel.FindingID("sha256:" + hex.EncodeToString(h.Sum(nil))[:16])
}

// NewFindingFromMetadata creates a Finding pre-populated with control metadata.
func NewFindingFromMetadata(m policy.ControlMetadata) Finding {
	return Finding{
		ControlID:          m.ID,
		ControlName:        m.Name,
		ControlDescription: m.Description,
		ControlSeverity:    m.Severity,
		ControlCompliance:  m.Compliance,
		ControlCCMV4:       m.CCMV4,
		ControlRemediation: m.Remediation,
		Exposure:           m.Exposure,
		Alternatives:       m.Alternatives,
		Classification:     m.Classification,
		ScopeTags:          m.ScopeTags,
		Defect:             m.Defect,
		Infection:          m.Infection,
		Failure:            m.Failure,
		Archetype:          m.Archetype,
		Scope:              m.Scope,
		CorpusReference:    m.CorpusReference,
	}
}
