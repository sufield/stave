package evaluation

import (
	"io"
	"slices"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
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

// Less defines the natural ordering of findings: by control ID, then asset ID,
// then WhyNow, then control name, then asset type.
func (f Finding) Less(other Finding) bool {
	if f.ControlID != other.ControlID {
		return f.ControlID < other.ControlID
	}
	if f.AssetID != other.AssetID {
		return f.AssetID < other.AssetID
	}
	if f.Evidence.WhyNow != other.Evidence.WhyNow {
		return f.Evidence.WhyNow < other.Evidence.WhyNow
	}
	if f.ControlName != other.ControlName {
		return f.ControlName < other.ControlName
	}
	return f.AssetType < other.AssetType
}

// SortFindings sorts a slice of findings by their natural ordering.
func SortFindings(fs []Finding) {
	slices.SortFunc(fs, func(a, b Finding) int {
		switch {
		case a.Less(b):
			return -1
		case b.Less(a):
			return 1
		default:
			return 0
		}
	})
}

// RemediationPlan describes deterministic, machine-readable remediation guidance.
type RemediationPlan struct {
	ID             string              `json:"id"`
	Target         RemediationTarget   `json:"target"`
	Preconditions  []string            `json:"preconditions,omitempty"`
	Actions        []RemediationAction `json:"actions,omitempty"`
	ExpectedEffect string              `json:"expected_effect,omitempty"`
}

type RemediationTarget struct {
	AssetID   asset.ID         `json:"asset_id"`
	AssetType kernel.AssetType `json:"asset_type"`
}

type RemediationAction struct {
	ActionType string `json:"action_type"`
	Path       string `json:"path"`
	Value      any    `json:"value,omitempty"`
}

// FindingDetail aggregates all context needed to understand and remediate
// a single violation: control metadata, asset context, evidence,
// predicate evaluation trace, remediation guidance, and next steps.
type FindingDetail struct {
	Control         FindingControlSummary   `json:"control"`
	Asset           FindingAssetSummary  `json:"asset"`
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
	Domain      string                   `json:"domain,omitempty"`
	Type        string                   `json:"type,omitempty"`
	ScopeTags   []string                 `json:"scope_tags,omitempty"`
	Compliance  policy.ComplianceMapping `json:"compliance,omitempty"`
	Exposure    *policy.Exposure         `json:"exposure,omitempty"`
}

// FindingAssetSummary holds asset metadata for the diagnosed finding.
type FindingAssetSummary struct {
	ID         asset.ID  `json:"id"`
	Type       string    `json:"type"`
	Vendor     string    `json:"vendor,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}

// TraceRenderer abstracts rendering of a predicate evaluation trace.
// Implemented by *trace.TraceResult, giving compile-time safety where
// callers previously type-asserted Raw.(any).
type TraceRenderer interface {
	RenderText(w io.Writer) error
	RenderJSON(w io.Writer) error
}

// FindingTrace wraps trace data for JSON serialization without importing
// the trace package from the domain layer. Populated by the service layer.
type FindingTrace struct {
	// Raw holds the serializable trace tree. The service layer sets this
	// to the trace.TraceResult value; renderers call RenderText/RenderJSON.
	Raw TraceRenderer `json:"-"`
	// FinalResult indicates whether the predicate matched.
	FinalResult bool `json:"final_result"`
}

// ControlProvider resolves an control definition by ID.
// The Result aggregate depends on this interface rather than a concrete
// collection, keeping the lookup contract in the domain while allowing
// any backing store (slice, map, repository) to satisfy it.
type ControlProvider interface {
	FindByID(kernel.ControlID) *policy.ControlDefinition
}

// FindingTraceBuilder builds a predicate evaluation trace for a finding.
// Defined as a function type so the service layer can inject the trace
// implementation without the domain importing the trace package.
type FindingTraceBuilder func(
	ctl *policy.ControlDefinition,
	assetID asset.ID,
	snapshots []asset.Snapshot,
	lastSeenUnsafeAt time.Time,
) *FindingTrace

// FindingDetailRequest holds the inputs for building a finding detail
// from within the Result aggregate.
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

// SuppressedFinding records a finding that was suppressed, with audit trail.
type SuppressedFinding struct {
	ControlID kernel.ControlID `json:"control_id"`
	AssetID   asset.ID         `json:"asset_id"`
	Reason    string           `json:"reason"`
	Expires   string           `json:"expires,omitempty"`
}
