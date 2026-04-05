package evaluation

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/core/predicate"
)

// Finding represents a detected control violation.
// A Finding is purely factual: evidence + classification, no advice.
type Finding struct {
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
}

// SortFindings sorts findings deterministically.
func SortFindings(fs []Finding) {
	slices.SortFunc(fs, func(a, b Finding) int {
		return cmp.Or(
			cmp.Compare(a.ControlID, b.ControlID),
			cmp.Compare(a.AssetID, b.AssetID),
			cmp.Compare(a.Evidence.WhyNow, b.Evidence.WhyNow),
			cmp.Compare(a.ControlName, b.ControlName),
			cmp.Compare(a.AssetType, b.AssetType),
		)
	})
}

// RemediationPlan describes deterministic, machine-readable remediation guidance.
type RemediationPlan struct {
	ID                 policy.RemediationPlanID `json:"id"`
	ActionsFingerprint string                   `json:"-"` // set by ComputeFingerprint, not serialized
	Target             RemediationTarget        `json:"target"`
	Preconditions      []string                 `json:"preconditions,omitempty"`
	Actions            []RemediationAction      `json:"actions,omitempty"`
	ExpectedEffect     string                   `json:"expected_effect,omitempty"`
}

// ComputeFingerprint sets ActionsFingerprint to a stable hash of the plan's actions.
// Call this before grouping so BuildGroups can operate without infrastructure ports.
func (p *RemediationPlan) ComputeFingerprint(h ports.Digester) {
	if len(p.Actions) == 0 {
		p.ActionsFingerprint = ""
		return
	}
	parts := make([]string, len(p.Actions))
	for i, a := range p.Actions {
		parts[i] = a.CanonicalKey()
	}
	slices.Sort(parts)
	p.ActionsFingerprint = string(h.Digest(parts, '\n'))[:16]
}

type RemediationTarget struct {
	AssetID   asset.ID         `json:"asset_id"`
	AssetType kernel.AssetType `json:"asset_type"`
}

// RemediationActionType identifies the kind of remediation action (e.g. "set").
type RemediationActionType string

// Canonical remediation action type identifiers.
const (
	ActionSet RemediationActionType = "set"
)

type RemediationAction struct {
	ActionType RemediationActionType `json:"action_type"`
	Path       predicate.FieldPath   `json:"path"`
	Value      any                   `json:"value,omitempty"`
}

// CanonicalKey returns a deterministic string representation for hashing.
func (a RemediationAction) CanonicalKey() string {
	val, _ := json.Marshal(a.Value)
	return fmt.Sprintf("%s|%s|%s", a.ActionType, a.Path.String(), val)
}

// FindingDetail aggregates all context needed to understand and remediate
// a single violation: control metadata, asset context, evidence,
// predicate evaluation trace, remediation guidance, and next steps.
type FindingDetail struct {
	Control         FindingControlSummary   `json:"control"`
	Asset           FindingAssetSummary     `json:"asset"`
	Evidence        Evidence                `json:"evidence"`
	Trace           *FindingTrace           `json:"trace,omitempty"`
	Remediation     *policy.RemediationSpec `json:"remediation,omitempty"`
	RemediationPlan *RemediationPlan        `json:"fix_plan,omitempty"`
	PostureDrift    *PostureDrift           `json:"posture_drift,omitempty"`
	NextSteps       []string                `json:"next_steps"`
}

// FindingControlSummary holds control metadata relevant to diagnosis.
type FindingControlSummary struct {
	ID          kernel.ControlID         `json:"id"`
	Name        string                   `json:"name"`
	Description string                   `json:"description"`
	Severity    policy.Severity          `json:"severity,omitempty"`
	Domain      kernel.AssetDomain       `json:"domain,omitempty"`
	Type        policy.ControlType       `json:"type,omitempty"`
	ScopeTags   []kernel.ScopeTag        `json:"scope_tags,omitempty"`
	Compliance  policy.ComplianceMapping `json:"compliance,omitempty"`
	Exposure    *policy.Exposure         `json:"exposure,omitempty"`
}

// FindingAssetSummary holds asset metadata for the diagnosed finding.
type FindingAssetSummary struct {
	ID         asset.ID         `json:"id"`
	Type       kernel.AssetType `json:"type"`
	Vendor     kernel.Vendor    `json:"vendor,omitempty"`
	ObservedAt time.Time        `json:"observed_at"`
}

// TraceRenderer abstracts rendering of a predicate evaluation trace.
// Implemented by *trace.Audit, giving compile-time safety where
// callers previously type-asserted Raw.(any).
type TraceRenderer interface {
	RenderText(w io.Writer) error
	RenderJSON(w io.Writer) error
}

// FindingTrace wraps trace data for JSON serialization without importing
// the trace package from the domain layer. Populated by the service layer.
type FindingTrace struct {
	// Raw holds the serializable trace tree. The service layer sets this
	// to the trace.Audit value; renderers call RenderText/RenderJSON.
	Raw TraceRenderer `json:"-"`
	// FinalResult indicates whether the predicate matched.
	FinalResult bool `json:"final_result"`
}

// ControlProvider resolves an control definition by ID.
// The Audit aggregate depends on this interface rather than a concrete
// collection, keeping the lookup contract in the domain while allowing
// any backing store (slice, map, repository) to satisfy it.
type ControlProvider interface {
	FindByID(kernel.ControlID) *policy.ControlDefinition
}

// TraceRequest groups the inputs for building a predicate evaluation trace.
type TraceRequest struct {
	Control    *policy.ControlDefinition
	AssetID    asset.ID
	Snapshots  []asset.Snapshot
	TargetTime time.Time
}

// FindingTraceBuilder builds a predicate evaluation trace for a finding.
// The domain defines this interface; the trace package provides the concrete
// implementation, keeping the domain free of trace-engine imports.
type FindingTraceBuilder interface {
	BuildTrace(req TraceRequest) *FindingTrace
}

// FindingDetailRequest holds the inputs for building a finding detail
// from within the Audit aggregate.
type FindingDetailRequest struct {
	ControlID    kernel.ControlID
	AssetID      asset.ID
	Controls     ControlProvider
	Snapshots    []asset.Snapshot
	TraceBuilder FindingTraceBuilder
}

// NewFindingFromMetadata creates a Finding pre-populated with control metadata.
// Callers fill in asset identity, evidence, and posture drift separately.
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
