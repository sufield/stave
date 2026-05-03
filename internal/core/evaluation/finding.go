package evaluation

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"slices"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
)

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

	// Owner routing — populated when a team manifest is loaded.
	OwnerTeamID     kernel.TeamID `json:"owner_team_id,omitempty"`
	OwnerTeamName   string        `json:"owner_team_name,omitempty"`
	OwnerContact    string        `json:"owner_contact,omitempty"`
	OwnerResolution string        `json:"owner_resolution_path,omitempty"`

	// Reachability — populated when IAM data is in the snapshot.
	Reachability *ReachabilityContext `json:"reachability,omitempty"`

	// ExposureScore is the priority score used to order findings. Populated
	// by the enrichment pass (internal/app/eval/workflow.go) after chain
	// membership is annotated. The zero value (kernel.ExposureScore(0))
	// means "not yet scored" — assessor.compileReport produces unscored
	// findings before the enrichment pass populates real scores.
	ExposureScore kernel.ExposureScore `json:"exposure_score,omitempty"`

	// ScoreBreakdown decomposes ExposureScore into the factors that produced
	// it. Populated alongside ExposureScore. Nil on unscored findings.
	ScoreBreakdown *risk.ScoreBreakdown `json:"score_breakdown,omitempty"`

	// ReasoningTrace lists the predicate leaf clauses that the engine
	// evaluated to produce this finding, each paired with the observed
	// value from the snapshot. For predicates rooted in `all:` (the
	// dominant shape in the catalog), every entry is a matched clause.
	// For predicates rooted in `any:`, entries are the full set of
	// evaluated clauses — the reader compares ObservedValue to
	// ExpectedValue to infer which satisfied the operator. Nil on
	// findings produced without a backing predicate (rare: compound
	// chain findings in report.ChainFindings).
	ReasoningTrace []MatchedClause `json:"reasoning_trace,omitempty"`

	// Defect / Infection / Failure carry the authored triage chain
	// from the control's YAML metadata (Andreas Zeller's Why Programs
	// Fail vocabulary applied to cloud misconfigurations). Empty on
	// controls that haven't been authored for the triage chain yet;
	// rendering surfaces skip empty sections rather than emit
	// placeholders.
	Defect    string `json:"defect,omitempty"`
	Infection string `json:"infection,omitempty"`
	Failure   string `json:"failure,omitempty"`

	// Archetype is the structural defect classification copied from the
	// control's archetype field. Empty when the control has no archetype.
	Archetype kernel.ArchetypeID `json:"archetype,omitempty"`

	// Delta is the mechanically-derived set of fix paths. Each
	// DeltaPath is an independent change that eliminates this finding.
	Delta []policy.DeltaPath `json:"delta,omitempty"`
}

// findingShadow is the wire-format projection used by Finding's
// custom MarshalJSON / UnmarshalJSON. It exposes the SLA fields
// under their original sla_* JSON tags so external consumers see
// the identical wire format regardless of whether the Go fields
// are exported. The Alias type-trick avoids infinite recursion:
// json.Marshal on *Alias does not recurse into Finding's
// MarshalJSON because Alias does not inherit the method set.
//
// Adding a new wire-only SLA shape here is the single edit
// required to extend the JSON contract — no code outside the
// evaluation package needs to change.
type findingShadow struct {
	*findingAlias
	SLADeadlineHours     *float64               `json:"sla_deadline_hours,omitempty"`
	SLABreached          bool                   `json:"sla_breached,omitempty"`
	SLAOverdueHours      *float64               `json:"sla_overdue_hours,omitempty"`
	SLAEscalatedSeverity policy.Severity        `json:"sla_escalated_severity,omitempty"`
	SLAPolicySource      kernel.SLAPolicySource `json:"sla_policy_source,omitempty"`
}

// findingAlias breaks the JSON method-set recursion: json.Marshal
// on (*findingAlias)(f) calls the default reflection-based
// marshaller instead of Finding's MarshalJSON.
type findingAlias Finding

// MarshalJSON projects the private SLA fields back to their
// original sla_* wire tags via the Shadow Struct pattern. The
// JSON output is byte-identical to the previous public-fields
// shape; consumers (FindingDTO, ASFF, SARIF wrappers, evidence
// bundles) parse the same payload.
func (f Finding) MarshalJSON() ([]byte, error) {
	alias := findingAlias(f)
	return json.Marshal(findingShadow{
		findingAlias:         &alias,
		SLADeadlineHours:     f.slaDeadlineHours,
		SLABreached:          f.slaBreached,
		SLAOverdueHours:      f.slaOverdueHours,
		SLAEscalatedSeverity: f.slaEscalatedSeverity,
		SLAPolicySource:      f.slaPolicySource,
	})
}

// UnmarshalJSON pairs with MarshalJSON so loaders that read the
// wire format reconstruct a Finding with its SLA state intact.
// The shadow's SLA fields are copied into the receiver's private
// slots; everything else flows through the alias's default
// reflection unmarshal.
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
	return nil
}

// IsCriticalSLABreach reports whether this finding is an SLA breach
// where either the original control severity or the SLA-escalated
// severity reaches Critical. Consumed by the apply runner to decide
// whether to set HasCriticalSLABreach on the run summary; the
// compound condition lives on the type so callers don't open-code
// the (SLABreached && severity-check) pair at every site.
func (f *Finding) IsCriticalSLABreach() bool {
	if !f.slaBreached {
		return false
	}
	return f.ControlSeverity == policy.SeverityCritical ||
		f.slaEscalatedSeverity == policy.SeverityCritical
}

// IsAnyBreach reports whether this finding has breached its SLA
// regardless of severity. Complements IsCriticalSLABreach by giving
// callers (the apply runner, gating logic) a named accessor for the
// "any breach happened" signal so they stop reading SLABreached
// directly — keeping the SLA state surface inside the type that
// owns the underlying fields.
func (f *Finding) IsAnyBreach() bool {
	return f != nil && f.slaBreached
}

// DwellHours returns the dwell time (Evidence.UnsafeDurationHours)
// the trend reports use for MTTR and total-dwell aggregations.
// Wraps the embedded Evidence field so trend / metrics callers ask
// the finding rather than reaching through Evidence directly.
func (f *Finding) DwellHours() float64 {
	if f == nil {
		return 0
	}
	return f.Evidence.UnsafeDurationHours
}

// ToDetail returns a FindingDetail seeded with the finding-owned
// fields (Evidence, PostureDrift, Asset summary). Caller-side fields
// — Control summary, Trace, Remediation, RemediationPlan, NextSteps —
// are populated by remediation.BuildFindingDetail after this call.
//
// Centralises the (AssetID, AssetType, AssetVendor, Evidence) →
// FindingAssetSummary projection so a future field addition on
// Finding lands once on this method instead of in every caller that
// builds a detail view.
func (f *Finding) ToDetail() FindingDetail {
	if f == nil {
		return FindingDetail{}
	}
	return FindingDetail{
		Evidence:     f.Evidence,
		PostureDrift: f.PostureDrift,
		Asset: FindingAssetSummary{
			ID:         f.AssetID,
			Type:       f.AssetType,
			Vendor:     f.AssetVendor,
			ObservedAt: f.Evidence.LastSeenUnsafeAt,
		},
	}
}

// MaxSeverityWith returns the higher of this finding's ControlSeverity
// and other. Centralises the
// (if f.ControlSeverity > maxSev { maxSev = f.ControlSeverity })
// pattern that identity-rank's direct/transitive max-severity loops
// reproduce twice. nil receiver returns other.
func (f *Finding) MaxSeverityWith(other policy.Severity) policy.Severity {
	if f == nil {
		return other
	}
	if other > f.ControlSeverity {
		return other
	}
	return f.ControlSeverity
}

// MatchesSeverityFilter reports whether this finding's severity is
// in the allowed-set passed by a filter. The allowed map keys are
// the canonical lowercase severity labels (SeverityLabel form).
// Empty / nil allowed-map matches every finding so callers can pass
// a single filter shape regardless of whether a severity restriction
// is active. Replaces the
// (filter.Severities[f.ControlSeverity.String()]) probe in
// telemetry/mapper.go's matchesFilter.
func (f *Finding) MatchesSeverityFilter(allowed map[string]bool) bool {
	if len(allowed) == 0 {
		return true
	}
	if f == nil {
		return false
	}
	return allowed[f.SeverityLabel()]
}

// SLAUrgencyFactor returns the multiplier the rank-priority pass
// applies to a finding's base risk score based on how close it is
// to (or past) its SLA threshold. Encapsulates the
// (RemainingHours, IsOverdue) → urgency-multiplier lookup that the
// roadmap builder used to compute inline against
// Evidence.ThresholdHours and Evidence.UnsafeDurationHours.
//
// Returns 1.0 when no SLA threshold is set so callers can multiply
// unconditionally — an unset threshold contributes no urgency.
//
// urgencyFn is the package-level multiplier function from the rank
// package; passing it as a parameter avoids importing the rank
// package from core (which would invert the dependency arrow). The
// caller (rank.BuildRoadmap) supplies SLAUrgencyMultiplier.
func (f *Finding) SLAUrgencyFactor(urgencyFn func(remainingHours float64, isOverdue bool) float64) float64 {
	if f == nil || urgencyFn == nil {
		return 1.0
	}
	remaining, hasSLA := f.Evidence.RemainingHours()
	if !hasSLA {
		return 1.0
	}
	return urgencyFn(remaining, f.Evidence.IsPastDue())
}

// SpanKey returns the canonical "<control_id>@<asset_id>" identifier
// the engine uses as a trace-span finding ID. Centralises the
// concatenation so the engine and any future trace consumer agree on
// the format. nil receiver returns "" so callers don't need to
// nil-guard before calling.
func (f *Finding) SpanKey() string {
	if f == nil {
		return ""
	}
	return string(f.ControlID) + "@" + string(f.AssetID)
}

// FallbackID returns a deterministic "<control_id>/<asset_id>"
// fingerprint used by the collector when a strategy emits a finding
// without a precomputed FindingID. Distinct from SpanKey: the
// collector path needs a slash separator to avoid ambiguity with
// ARN-shaped asset IDs that contain colons. Centralises the format
// so the collector and any future fallback site stay aligned.
func (f *Finding) FallbackID() string {
	if f == nil {
		return ""
	}
	return string(f.ControlID) + "/" + string(f.AssetID)
}

// HasDiagnosis reports whether the finding carries any of the
// authored triage prose (Defect / Infection / Failure). Renderers
// used to ask `f.Defect == "" && f.Infection == "" && f.Failure == ""`
// directly; centralising the check here means a future fourth field
// in the chain (or a rename) is one edit on the type.
func (f *Finding) HasDiagnosis() bool {
	return f != nil && (f.Defect != "" || f.Infection != "" || f.Failure != "")
}

// HasReasoningTrace reports whether the finding carries the
// predicate-clause reasoning trace the engine emits when a control
// matches. Replaces the `len(f.ReasoningTrace) == 0` probe in text
// renderers.
func (f *Finding) HasReasoningTrace() bool {
	return f != nil && len(f.ReasoningTrace) > 0
}

// HasDelta reports whether the finding carries any mechanically-
// derived fix paths. Replaces the `len(f.Delta) == 0` probe so the
// renderer stops asking the slice and asks the finding.
func (f *Finding) HasDelta() bool {
	return f != nil && len(f.Delta) > 0
}

// ToFailingControl projects the finding to the (control, asset) pair
// the chain / attack-stage analysis consumes. Centralising the field
// extraction here means a future addition to FailingControl (e.g. a
// region or scope_tags hint) lands once on the producer side instead
// of being threaded through every enrichment caller.
func (f *Finding) ToFailingControl() risk.FailingControl {
	if f == nil {
		return risk.FailingControl{}
	}
	return risk.FailingControl{
		ControlID: f.ControlID,
		AssetID:   f.AssetID,
	}
}

// ToRankInput projects the finding to the input shape the exposure
// ranking consumes. The 6-field copy used to live inline in
// internal/app/eval/workflow.go; moving it here keeps the
// finding-to-rank-input contract on the type that owns the source
// fields so a future Evidence-field rename only edits one site.
func (f *Finding) ToRankInput() risk.RankInput {
	if f == nil {
		return risk.RankInput{}
	}
	return risk.RankInput{
		ControlID:            f.ControlID,
		AssetID:              f.AssetID,
		ControlSeverity:      f.ControlSeverity,
		Exposure:             f.Exposure,
		UnsafeDurationHours:  f.Evidence.UnsafeDurationHours,
		ChainMembershipCount: len(f.ChainMembership),
	}
}

// PrimaryChainSeverity returns the severity of the first chain this
// finding participates in, or "" if the finding is not a chain
// member. The "primary" chain is the first entry in ChainMembership;
// chain detection appends in deterministic order so this is stable
// across runs.
func (f *Finding) PrimaryChainSeverity() string {
	if f == nil || len(f.ChainMembership) == 0 {
		return ""
	}
	return f.ChainMembership[0].ChainSeverity.String()
}

// PrimaryChainID returns the ID of the first chain this finding
// participates in, or "" if the finding is not a chain member.
func (f *Finding) PrimaryChainID() string {
	if f == nil || len(f.ChainMembership) == 0 {
		return ""
	}
	return string(f.ChainMembership[0].ChainID)
}

// ComputeBaseScore returns the per-finding base exposure score the
// remediation roadmap uses when the chain-aware top-N ranker has not
// produced a precomputed score for this finding (e.g. assets that
// did not enter the top-N batch). The math mirrors the formula in
// risk.RankExposures: severity weight × duration factor × blind
// multiplier. Callers receive the score and the breakdown together
// so the roadmap entry can populate ScoreBreakdown without a second
// pass over the same fields.
func (f *Finding) ComputeBaseScore() (float64, risk.ScoreBreakdown) {
	if f == nil {
		return 0, risk.ScoreBreakdown{}
	}
	base := f.ControlSeverity.Weight()
	daysBlind := f.Evidence.UnsafeDurationHours / 24.0
	durFactor := risk.DurationFactor(f.Evidence.UnsafeDurationHours)
	blindMult := risk.BlindMultiplier(daysBlind)
	score := float64(base) * durFactor * blindMult
	return score, risk.ScoreBreakdown{
		BaseScore:          base,
		DurationFactor:     durFactor,
		BlastMultiplier:    1.0,
		ExposureMultiplier: 1.0,
		BlindMultiplier:    blindMult,
		DaysBlind:          daysBlind,
	}
}

// IsOverdue reports whether the finding has breached SLA AND the
// overdue duration is recorded. Replaces the
// `f.slaBreached && f.slaOverdueHours != nil` pair that recurs
// across rank/priority, rank/formatter/csv, and graph/builder.
//
// The two-field check matters: a finding can be SLABreached without
// an SLAOverdueHours when the SLA evaluator runs in a degraded
// mode (no deadline configured). Treating SLABreached alone as
// "overdue" inflated counters in those cases.
func (f *Finding) IsOverdue() bool {
	return f.slaBreached && f.slaOverdueHours != nil
}

// HasSLA reports whether an SLA deadline applies to this finding.
// Replaces the (f.slaDeadlineHours != nil) nil-check that recurred
// across cmd/trend/team_trend.go, cmd/trend/run.go,
// cmd/trend/metrics.go, cmd/collect/cmd.go, and
// cmd/export/compliance/output.go. Centralising the presence check
// keeps the SLA-state surface on the type that owns the pointer.
func (f *Finding) HasSLA() bool {
	return f != nil && f.slaDeadlineHours != nil
}

// SLADeadlineValue returns the SLA deadline in hours together with
// a presence indicator. Replaces patterns that dereferenced
// f.slaDeadlineHours after a separate nil check; callers can pass
// the (value, ok) pair through their formatters without touching
// the underlying pointer.
func (f *Finding) SLADeadlineValue() (float64, bool) {
	if f == nil || f.slaDeadlineHours == nil {
		return 0, false
	}
	return *f.slaDeadlineHours, true
}

// OverdueHours returns the number of hours past SLA, with a presence
// indicator. Returns (0, false) when the finding is not overdue or
// has no recorded overdue duration. Replaces the raw
// (*f.slaOverdueHours) dereference in cmd/export/compliance/output.go
// and callers that need the value without re-checking the nil.
func (f *Finding) OverdueHours() (float64, bool) {
	if f == nil || f.slaOverdueHours == nil {
		return 0, false
	}
	return *f.slaOverdueHours, true
}

// RehydrateSLA restores the SLA state from previously-serialised
// wire fields. Used by loaders / library converters that
// reconstruct a Finding from JSON (or from a public mirror like
// pkg/stave.Finding); the AnnotateSLA invariant — only the
// evaluation package writes the SLA fields — is preserved
// because RehydrateSLA itself lives in the evaluation package
// and accepts the wire shape as input.
//
// The escalated severity carries through as-is; if the snapshot
// did not capture an escalation, callers pass policy.SeverityNone.
func (f *Finding) RehydrateSLA(deadline *float64, breached bool, overdue *float64, escalated policy.Severity, source kernel.SLAPolicySource) {
	if f == nil {
		return
	}
	f.slaDeadlineHours = deadline
	f.slaBreached = breached
	f.slaOverdueHours = overdue
	f.slaEscalatedSeverity = escalated
	f.slaPolicySource = source
}

// SLAEscalatedSeverityValue returns the escalated severity the SLA
// evaluator computed for this finding (Critical when dwell time
// has rolled the original severity past the catalog ladder).
// Returns SeverityNone when no escalation applied.
func (f *Finding) SLAEscalatedSeverityValue() policy.Severity {
	if f == nil {
		return policy.SeverityNone
	}
	return f.slaEscalatedSeverity
}

// SLAPolicySourceLabel returns the SLA policy source's wire-format
// label ("control_override", "profile:<id>", or "" when no SLA
// applies). Replaces the f.slaPolicySource.String() probe.
func (f *Finding) SLAPolicySourceLabel() string {
	if f == nil {
		return ""
	}
	return f.slaPolicySource.String()
}

// SLAPolicySourceValue returns the typed SLA policy source. Use
// when comparing against kernel.SLAPolicySource constants;
// renderers prefer SLAPolicySourceLabel.
func (f *Finding) SLAPolicySourceValue() kernel.SLAPolicySource {
	if f == nil {
		return ""
	}
	return f.slaPolicySource
}

// SLADeadlinePtr returns the SLA deadline as a *float64 — same
// pointer shape the wire format and DTO use. Nil when no deadline
// applies. For boolean / numeric inspection prefer HasSLA,
// IsOverdue, SLADeadlineValue.
func (f *Finding) SLADeadlinePtr() *float64 {
	if f == nil {
		return nil
	}
	return f.slaDeadlineHours
}

// SLAOverduePtr returns the SLA-overdue dwell as a *float64. See
// SLADeadlinePtr for the pointer-shape rationale.
func (f *Finding) SLAOverduePtr() *float64 {
	if f == nil {
		return nil
	}
	return f.slaOverdueHours
}

// SLABreachedFlag returns the raw boolean. Use only when copying
// the SLA triple into a DTO that mirrors the wire shape;
// otherwise prefer the predicate methods (IsAnyBreach, IsOverdue,
// SLAContribution).
func (f *Finding) SLABreachedFlag() bool {
	return f != nil && f.slaBreached
}

// HasSource reports whether the finding carries a SourceRef
// (file/line annotation from the originating extractor). Replaces
// the (f.Source != nil) probe in the DTO mapper.
func (f *Finding) HasSource() bool {
	return f != nil && f.Source != nil
}

// HasExposure reports whether the finding carries the catalog's
// authored Exposure block. Replaces (f.Exposure != nil) probes.
func (f *Finding) HasExposure() bool {
	return f != nil && f.Exposure != nil
}

// HasPostureDrift reports whether the finding carries
// recurrence-pattern data. Replaces (f.PostureDrift != nil) probes.
func (f *Finding) HasPostureDrift() bool {
	return f != nil && f.PostureDrift != nil
}

// HasAlternatives reports whether the catalog declared
// alternative-tool mappings for the finding's control. Replaces
// (len(f.Alternatives) > 0) probes.
func (f *Finding) HasAlternatives() bool {
	return f != nil && len(f.Alternatives) > 0
}

// TemporalRiskMessage returns the Evidence-side risk message
// catalog authors attach to a finding (e.g. "asset has been
// unsafe for 4 days, exceeding the 7-day SLA"). Centralised so
// renderers stop reaching into Evidence.TemporalRisk directly —
// keeps the Evidence-field probe on the type that owns it.
func (f *Finding) TemporalRiskMessage() string {
	if f == nil {
		return ""
	}
	return f.Evidence.TemporalRisk
}

// SLAStats is the per-finding SLA contribution surfaced by
// SLAContribution. Renderers and aggregators consume one struct
// rather than three accessors (HasSLA, IsOverdue, OverdueHours)
// in sequence.
//
//   - Detected is 1 when an SLA deadline applies to this finding.
//   - Breached is 1 when the deadline has been exceeded.
//   - WithinSLA is 1 when the deadline applies but is not yet
//     breached. Detected = Breached + WithinSLA.
//   - OverdueHours is the dwell-time excess past the deadline.
type SLAStats struct {
	Detected     int
	Breached     int
	WithinSLA    int
	OverdueHours float64
}

// SLAContribution returns this finding's contribution to an SLA
// rollup. Replaces the (HasSLA / IsOverdue / OverdueHours)
// triple-call pattern in cmd/export/compliance/output.go and
// similar accumulators so a future SLA-shape change is one edit
// on the type.
func (f *Finding) SLAContribution() SLAStats {
	if f == nil || !f.HasSLA() {
		return SLAStats{}
	}
	out := SLAStats{Detected: 1}
	if f.IsOverdue() {
		out.Breached = 1
		if h, ok := f.OverdueHours(); ok {
			out.OverdueHours = h
		}
	} else {
		out.WithinSLA = 1
	}
	return out
}

// IsCritical reports whether this finding's control severity is
// Critical. Replaces the
// strings.EqualFold(f.ControlSeverity.String(), "critical") pattern
// at cmd/trend/team_trend.go:113 with a typed comparison that does
// not depend on string-rendering of the severity enum.
func (f *Finding) IsCritical() bool {
	return f != nil && f.ControlSeverity == policy.SeverityCritical
}

// IsHighOrAbove reports whether this finding's control severity is
// High or Critical. Used by ranking / prioritisation code that
// needs the "important enough to surface" threshold.
func (f *Finding) IsHighOrAbove() bool {
	return f != nil && f.ControlSeverity >= policy.SeverityHigh
}

// SeverityLabel returns the canonical lowercase severity string for
// this finding. Centralises the .ControlSeverity.String() calls
// scattered across cmd/trend/{metrics,forecast,mttr},
// cmd/apply/run_newonly, and cmd/exempt/export so a future enum
// rename or label-format change is one edit. Mirrors
// diag.Finding.SeverityLabel for the diagnostic side.
func (f *Finding) SeverityLabel() string {
	if f == nil {
		return ""
	}
	return f.ControlSeverity.String()
}

// HasOwner reports whether ownership routing has populated a team
// for this finding. Used by trend / metrics / watch to skip the
// per-team rollup when no owner manifest is loaded. Bypassing this
// accessor (e.g. cmd/metrics/cmd.go, cmd/apply/run_owners.go) is
// the legacy pattern OwnerKey + MatchesOwner replace.
func (f *Finding) HasOwner() bool {
	return !f.OwnerTeamID.IsEmpty()
}

// OwnerKey returns the owning team's ID rendered as a string, the
// shape every owner-aware caller needs for map keys and CLI filters.
// Replaces the string(f.OwnerTeamID) conversions at
// cmd/metrics/cmd.go:84 and cmd/apply/run_owners.go:64. Returns ""
// when no owner is set so callers can branch on a single string
// value instead of mixing nil / empty checks.
func (f *Finding) OwnerKey() string {
	if f == nil || !f.HasOwner() {
		return ""
	}
	return f.OwnerTeamID.String()
}

// MatchesOwner reports whether this finding's owner key is present
// in the supplied allow-set. Encapsulates the
// (allowed[string(f.OwnerTeamID)]) lookup pattern in
// cmd/apply/run_owners.go so the filter site stops doing the type
// conversion and map probe inline. nil receiver returns false; nil
// allowed-map returns false (no allow-set means nothing matches).
func (f *Finding) MatchesOwner(allowed map[string]bool) bool {
	if f == nil || allowed == nil {
		return false
	}
	return allowed[f.OwnerKey()]
}

// IsChainMember reports whether the finding contributed to one or
// more fired chains. Sorting and rendering paths use this to push
// chain participants ahead of single-control violations.
func (f *Finding) IsChainMember() bool {
	return len(f.ChainMembership) > 0
}

// ReasoningTraceFromMisconfigurations converts a predicate-extracted
// misconfiguration list into the reasoning-trace shape surfaced on a
// finding. The two carry the same triggering state from slightly
// different angles: Misconfiguration is the failed-logic-gate framing
// (used by Evidence), MatchedClause is the predicate-match-record
// framing (used by ReasoningTrace).
//
// See docs/product/metrics.md § Metric 3 for the inline-trace
// specification and the "shared predicate-consumed observation
// fields" framing that Metric 2 (Deduplication) will consume.
func ReasoningTraceFromMisconfigurations(ms []policy.Misconfiguration) []MatchedClause {
	if len(ms) == 0 {
		return nil
	}
	out := make([]MatchedClause, len(ms))
	for i, mc := range ms {
		key := mc.DisplayProperty()
		expected := mc.UnsafeValue
		out[i] = MatchedClause{
			PredicateExpr:  formatClauseExpr(key, mc.Operator, expected),
			ObservationKey: kernel.FromFieldPath(key),
			Operator:       mc.Operator,
			ExpectedValue:  expected,
			ObservedValue:  mc.ActualValue,
		}
	}
	return out
}

// formatClauseExpr renders the clause in the authored form for display.
func formatClauseExpr(key string, op predicate.Operator, expected any) string {
	switch expected.(type) {
	case nil:
		return key + " " + string(op)
	default:
		return key + " " + string(op) + " " + stringifyExpected(expected)
	}
}

// stringifyExpected returns a compact display form of the expected value.
// Strings are quoted; other scalars use default Go formatting.
func stringifyExpected(v any) string {
	switch t := v.(type) {
	case string:
		return "\"" + t + "\""
	default:
		return fmt.Sprint(t)
	}
}

// MatchedClause records one predicate leaf clause and the observed
// value that triggered (or was considered in) the fire. See
// docs/product/metrics.md § Metric 3 for semantics.
type MatchedClause struct {
	// PredicateExpr is the authored form of the clause, e.g.
	// "storage.access.public_read eq true" — convenient for display.
	PredicateExpr string `json:"predicate_expr"`
	// ObservationKey is the field path the clause consumed, with the
	// "properties." prefix stripped for readability.
	ObservationKey kernel.ObservationKey `json:"observation_key"`
	// Operator is the clause's op, e.g. "eq", "any_in_field".
	Operator predicate.Operator `json:"operator"`
	// ExpectedValue is the value the clause expected (or the param
	// reference when the value was `params.<name>`).
	ExpectedValue any `json:"expected_value,omitempty"`
	// ObservedValue is the value resolved from the snapshot at
	// ObservationKey. Nil when the field is absent from the
	// observation.
	ObservedValue any `json:"observed_value,omitempty"`
}

// ReachabilityContext carries IAM reachability data for a finding.
type ReachabilityContext struct {
	TotalReachablePrincipals   int                 `json:"total_reachable_principals"`
	PrivilegedPrincipalCount   int                 `json:"privileged_principal_count"`
	HighestPrivilegePrincipal  kernel.PrincipalRef `json:"highest_privilege_principal,omitempty"`
	ExternalPrincipalReachable bool                `json:"external_principal_reachable,omitempty"`
	BlastRadiusScore           kernel.BlastRadius  `json:"blast_radius_score"`
}

// ChainMembershipEntry records that a finding contributed to a fired chain.
type ChainMembershipEntry struct {
	// ChainID is the chain definition ID (e.g. "data_exfiltration_path").
	ChainID kernel.ChainID `json:"chain_id"`

	// ChainSeverity is the compound severity of the chain.
	ChainSeverity policy.Severity `json:"chain_severity"`

	// StageSpan is the attack stage progression of the chain,
	// sorted by kill chain order.
	StageSpan []kernel.AttackStage `json:"stage_span"`

	// Narrative is the chain's human-readable description.
	Narrative string `json:"narrative"`
}

// SortFindings sorts findings by actionable priority:
// ExposureScore descending (highest-score findings first), with
// alphabetical tiebreaker on ControlID + AssetID (and further
// fallbacks) so the order stays deterministic when scores collide
// or when the sort is called before scoring runs.
//
// Unscored findings (ExposureScore == 0, e.g. during
// assessor.compileReport before the enrichment pass populates
// scores) fall through to the alphabetical tiebreaker, matching the
// previous sort semantics in that window.
func SortFindings(fs []Finding) {
	slices.SortFunc(fs, func(a, b Finding) int {
		return cmp.Or(
			// Primary: ExposureScore descending.
			cmp.Compare(b.ExposureScore, a.ExposureScore),
			// Tiebreaker: deterministic alphabetical ordering.
			cmp.Compare(a.ControlID, b.ControlID),
			cmp.Compare(a.AssetID, b.AssetID),
			cmp.Compare(a.FindingID, b.FindingID),
			cmp.Compare(a.ControlName, b.ControlName),
			cmp.Compare(a.AssetType, b.AssetType),
		)
	})
}

// StableFindingID computes a deterministic fingerprint for a (control, asset) pair.
// Same inputs always produce the same ID, enabling cross-run finding correlation.
func StableFindingID(ctlID kernel.ControlID, astID asset.ID) kernel.FindingID {
	h := sha256.New()
	h.Write([]byte("finding:"))
	h.Write([]byte(ctlID))
	h.Write([]byte(":"))
	h.Write([]byte(astID))
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
	}
}

// ExceptedFinding records a finding that was excepted, with audit trail.
type ExceptedFinding struct {
	ControlID kernel.ControlID  `json:"control_id"`
	AssetID   asset.ID          `json:"asset_id"`
	Reason    string            `json:"reason"`
	Expires   policy.ExpiryDate `json:"expires"`
}

// HasExpiry reports whether this exception carries an expiry
// date. Replaces the (!s.Expires.IsZero()) probe in renderers so
// the field check stays on the type that owns Expires.
func (e *ExceptedFinding) HasExpiry() bool {
	return e != nil && !e.Expires.IsZero()
}

// WriteText renders the exception as a single grep-friendly text
// line: "<control> on <asset> — <reason>" with " (expires <date>)"
// appended when an expiry is recorded. Centralises the renderer
// so callers stop reaching into Expires / Reason directly.
func (e *ExceptedFinding) WriteText(w io.Writer) {
	if e == nil {
		return
	}
	fmt.Fprintf(w, "%s on %s — %s", e.ControlID, e.AssetID, e.Reason)
	if e.HasExpiry() {
		fmt.Fprintf(w, " (expires %s)", e.Expires)
	}
	fmt.Fprintln(w)
}
