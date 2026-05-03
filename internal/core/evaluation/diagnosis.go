package evaluation

import (
	"io"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

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

// HasPostureDrift reports whether the diagnosis carries
// recurrence-pattern data. Replaces the (PostureDrift != nil)
// probe in detail renderers so the optional-pointer concern stays
// on the type that owns the field.
func (d *FindingDetail) HasPostureDrift() bool {
	return d != nil && d.PostureDrift != nil
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

// ExposureSummary returns the (type, principal-scope) pair the
// catalog's Exposure block exposes for renderers. ok = false
// when the summary has no Exposure annotation. Mirrors
// controldef.ControlDefinition.ExposureSummary so renderers
// branching on either type carry the same predicate shape.
func (s FindingControlSummary) ExposureSummary() (exposureType, principalScope string, ok bool) {
	if s.Exposure == nil {
		return "", "", false
	}
	return string(s.Exposure.Type), s.Exposure.PrincipalScope.String(), true
}

// FindingAssetSummary holds asset metadata for the diagnosed finding.
type FindingAssetSummary struct {
	ID         asset.ID         `json:"id"`
	Type       kernel.AssetType `json:"type"`
	Vendor     kernel.Vendor    `json:"vendor,omitempty"`
	ObservedAt time.Time        `json:"observed_at"`
}

// TraceRenderer abstracts rendering of a predicate evaluation trace.
type TraceRenderer interface {
	RenderText(w io.Writer) error
	RenderJSON(w io.Writer) error
}

// FindingTrace wraps trace data for JSON serialization without importing
// the trace package from the domain layer.
type FindingTrace struct {
	Raw         TraceRenderer `json:"-"`
	FinalResult bool          `json:"final_result"`
}

// ControlProvider resolves a control definition by ID.
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
type FindingTraceBuilder interface {
	BuildTrace(req TraceRequest) *FindingTrace
}

// FindingDetailRequest holds the inputs for building a finding detail.
type FindingDetailRequest struct {
	ControlID    kernel.ControlID
	AssetID      asset.ID
	Controls     ControlProvider
	Snapshots    []asset.Snapshot
	TraceBuilder FindingTraceBuilder
}
