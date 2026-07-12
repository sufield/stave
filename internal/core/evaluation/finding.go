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
	"github.com/sufield/stave/internal/core/findings"
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
	ScoreBreakdown *findings.ScoreBreakdown `json:"score_breakdown,omitempty"`

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

	// Scope is the cardinality of the control's predicate reasoning:
	// "atomic" (single asset) or "compound" (multi-asset). Copied
	// from the control's scope field. Empty for unclassified
	// controls.
	Scope string `json:"control_scope,omitempty"`

	// CorpusReference cites the real-world attack pattern this
	// control detects. Copied from the control's corpus_reference
	// field. Required when Scope == "compound" — the build-time
	// validator enforces it on the catalog side.
	CorpusReference string `json:"corpus_reference,omitempty"`

	// Delta is the mechanically-derived set of fix paths. Each
	// DeltaPath is an independent change that eliminates this finding.
	Delta []policy.DeltaPath `json:"delta,omitempty"`

	// ContributingFactIDs lists the SIR fact_ids that describe the
	// asset this finding fired on. Each id matches the `fact_id`
	// emitted by `stave export-sir --format jsonl` and the
	// `;; fact_id:` annotation in `stave export-sir --format smt2`,
	// closing the trace from a CEL finding back to the specific
	// observation property and engine assertion that share the same
	// asset. Populated post-evaluation by applycore when SIR
	// projection succeeds; empty otherwise (omitempty preserves
	// the prior wire shape for consumers that don't read it).
	ContributingFactIDs []string `json:"contributing_fact_ids,omitempty"`
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
//
// Pointer receiver so json.Marshal does not copy the ~700-byte
// Finding on every encode call.
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

// SLA state vocabulary on Finding. The four predicates form a
// strict-subset ladder; pick the loosest one that answers the
// caller's actual question.
//
//	HasSLA()              ← a deadline applies (the SLA evaluator
//	                        attached one). Says nothing about
//	                        whether it was met.
//	IsAnyBreach()         ← the breach flag is set. The overdue
//	                        duration may not be captured (degraded
//	                        mode when the evaluator runs without a
//	                        timestamped deadline). Use for boolean
//	                        rollups (count of breached, gating).
//	IsOverdue()           ← breached AND the overdue duration was
//	                        recorded. Use when the value will be
//	                        dereferenced (the renderer that prints
//	                        "%.0fh overdue").
//	IsCriticalSLABreach() ← breached AND the original or escalated
//	                        severity reaches Critical. The
//	                        gating-side "must block CI" predicate.
//
// Ladder direction: HasSLA ⊇ IsAnyBreach ⊇ IsOverdue (overdue
// implies breach implies tracked). IsCriticalSLABreach is a
// strictly tighter version of IsAnyBreach (severity-bounded), not
// of IsOverdue — a critical breach can fire without an overdue
// duration recorded.
//
// IsUnattributed reports whether this finding lacks a ControlID,
// meaning it cannot be linked back to a specific rule. Such findings
// cannot be safely indexed by control identity (the FallbackID
// helper would coalesce all unattributed rows into the same key,
// silently merging distinct findings into one), so collectors and
// reporters drop them rather than carrying anonymous evidence.
func (f *Finding) IsUnattributed() bool {
	if f == nil {
		return true
	}
	return f.ControlID == ""
}

// IsCriticalSLABreach reports whether this finding is an SLA breach
// where either the original control severity or the SLA-escalated
// severity reaches Critical. Consumed by the apply runner to decide
// whether to set HasCriticalSLABreach on the run summary.
func (f *Finding) IsCriticalSLABreach() bool {
	if !f.slaBreached {
		return false
	}
	return f.ControlSeverity == policy.SeverityCritical ||
		f.slaEscalatedSeverity == policy.SeverityCritical
}

// IsAnyBreach reports whether this finding has breached its SLA,
// regardless of severity OR overdue-duration capture. Use for
// counters, gating booleans, and CSV status columns where only
// the "did the breach happen" signal matters; prefer IsOverdue
// when the renderer will dereference the overdue hours value.
//
// See the SLA state vocabulary on IsCriticalSLABreach for the
// full ladder.
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

// DwellDays returns the dwell time in days. Centralised so callers
// stop dividing UnsafeDurationHours by 24 inline at every ticket /
// outlier / remediation-impact site.
func (f *Finding) DwellDays() float64 {
	return f.DwellHours() / 24.0
}

// IsTemporallySignificant reports whether the finding has enough
// temporal data — historical lifecycle dates OR a non-zero current
// duration — to be a reportable, "live" violation rather than an
// unanchored noise event (a brand-new resource with no measured
// dwell yet, or a fixture with no captured timestamps). The
// renderer / scorer / report pipeline filters on this so first-run
// observations don't fire as alerts before they accumulate weight.
//
// Pure projection on the finding's own Evidence: callers don't pass
// in a separate snapshot, the evidence already reflects the
// current observation's UnsafeDurationHours.
func (f *Finding) IsTemporallySignificant() bool {
	if f == nil {
		return false
	}
	return f.Evidence.HasLifecycleDates() || f.Evidence.UnsafeDurationHours > 0
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
func (f *Finding) MatchesSeverityFilter(allowed map[string]struct{}) bool {
	if len(allowed) == 0 {
		return true
	}
	if f == nil {
		return false
	}
	_, ok := allowed[f.SeverityLabel()]
	return ok
}

// SLAUrgencyFactor returns the multiplier the rank-priority pass
// applies to a finding's base risk score based on how close it is to
// (or past) its SLA POLICY deadline.
//
// Urgency is computed against f.slaDeadlineHours — the deadline
// AnnotateSLA derives from the SLA profile (or control override) — NOT
// against Evidence.ThresholdHours (the control's max_unsafe_duration).
// The two are distinct: a finding exists precisely because the unsafe
// dwell already exceeded the control threshold, so the threshold-based
// "remaining" is always negative and would pin every finding at maximum
// urgency. The SLA deadline is a separate policy clock the operator sets
// for remediation, and remaining = deadline − dwell is genuinely
// positive while a finding is still within its SLA.
//
// Returns 1.0 when the finding carries no SLA deadline (AnnotateSLA was
// not run, or the profile sets no deadline for this severity) so callers
// can multiply unconditionally — no policy clock means no urgency.
//
// urgencyFn is the package-level multiplier function from the rank
// package; passing it as a parameter avoids importing the rank package
// from core (which would invert the dependency arrow). The caller
// (rank.BuildRoadmap) supplies SLAUrgencyMultiplier.
func (f *Finding) SLAUrgencyFactor(urgencyFn func(remainingHours float64, isOverdue bool) float64) float64 {
	if f == nil || urgencyFn == nil {
		return 1.0
	}
	deadline, hasSLA := f.SLADeadlineValue()
	if !hasSLA {
		return 1.0
	}
	remaining := deadline - f.Evidence.UnsafeDurationHours
	return urgencyFn(remaining, f.IsOverdue())
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

// TriageEntry pairs an authored-triage label with its prose. Used
// by renderers iterating Defect / Infection / Failure as one
// labelled list rather than three separate (label, value) pairs
// at the call site.
type TriageEntry struct {
	Label string
	Text  string
}

// TriageEntries returns the non-empty triage prose attached to
// the finding in the canonical Defect → Infection → Failure
// order. Renderers consume the slice and emit one row per entry;
// missing fields disappear from the output without the caller
// branching on each one. Empty receiver returns nil.
func (f *Finding) TriageEntries() []TriageEntry {
	if f == nil {
		return nil
	}
	var out []TriageEntry
	if f.Defect != "" {
		out = append(out, TriageEntry{Label: "Defect", Text: f.Defect})
	}
	if f.Infection != "" {
		out = append(out, TriageEntry{Label: "Infection", Text: f.Infection})
	}
	if f.Failure != "" {
		out = append(out, TriageEntry{Label: "Failure", Text: f.Failure})
	}
	return out
}

// HasObservableDiagnosis reports whether the finding carries both
// authored triage prose AND a reasoning trace — the joint condition
// the text renderer uses to decide whether to print the OBSERVED
// section. Single predicate replaces the
// (HasDiagnosis() && HasReasoningTrace()) compound check at the
// renderer site.
func (f *Finding) HasObservableDiagnosis() bool {
	return f.HasDiagnosis() && f.HasReasoningTrace()
}

// HasDeltaDiagnosis reports whether the finding carries both
// authored triage prose AND a mechanically-derived delta — the
// joint condition the text renderer uses to decide whether to
// print the DELTA section. Sibling of HasObservableDiagnosis.
func (f *Finding) HasDeltaDiagnosis() bool {
	return f.HasDiagnosis() && f.HasDelta()
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
		ChainMembershipCount: f.ChainMembershipCount(),
	}
}

// ChainMembershipCount returns the number of chains this finding
// participates in. Wraps the embedded slice length so callers
// (RankInput projection, chain-membership tests) stop reading
// `len(f.ChainMembership)` directly.
func (f *Finding) ChainMembershipCount() int {
	if f == nil {
		return 0
	}
	return len(f.ChainMembership)
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

// PrimaryChainNarrative returns the narrative attached to the
// first chain this finding participates in, or "" if the finding
// is not a chain member. Sibling of PrimaryChainID /
// PrimaryChainSeverity for the renderer that needs the prose
// alongside the IDs.
func (f *Finding) PrimaryChainNarrative() string {
	if f == nil || len(f.ChainMembership) == 0 {
		return ""
	}
	return f.ChainMembership[0].Narrative
}

// PrimaryChainStageSpan returns the StageSpan slice of the first
// chain this finding participates in, or nil when the finding is
// not a chain member. Used by the SARIF renderer's chain-context
// properties bag so the per-stage list lives on the type.
func (f *Finding) PrimaryChainStageSpan() []kernel.AttackStage {
	if f == nil || len(f.ChainMembership) == 0 {
		return nil
	}
	return f.ChainMembership[0].StageSpan
}

// ChainIDs returns every chain ID the finding contributes to, in
// catalogue order. Nil slice for non-chain findings so range loops
// behave the same as on an empty membership.
func (f *Finding) ChainIDs() []kernel.ChainID {
	if f == nil || len(f.ChainMembership) == 0 {
		return nil
	}
	out := make([]kernel.ChainID, len(f.ChainMembership))
	for i := range f.ChainMembership {
		out[i] = f.ChainMembership[i].ChainID
	}
	return out
}

// ChainMembershipProperties returns the per-chain property maps
// the graph builder embeds on a finding node's
// `x_stave_chain_membership` extension. Each entry carries
// chain_id, chain_severity, and narrative; stage_span is left for
// callers that need ATT&CK projections (the graph builder applies
// attack.TranslateStages on top of this slice's entries).
//
// Centralising the map shape here keeps the wire format stable
// across producers — any future addition lands in one place.
func (f *Finding) ChainMembershipProperties() []map[string]any {
	if f == nil || len(f.ChainMembership) == 0 {
		return nil
	}
	out := make([]map[string]any, len(f.ChainMembership))
	for i, cm := range f.ChainMembership {
		out[i] = map[string]any{
			"chain_id":       cm.ChainID,
			"chain_severity": cm.ChainSeverity,
			"stage_span":     cm.StageSpan,
			"narrative":      cm.Narrative,
		}
	}
	return out
}

// ComputeBaseScore returns the per-finding base exposure score the
// remediation roadmap uses when the chain-aware top-N ranker has not
// produced a precomputed score for this finding (e.g. assets that
// did not enter the top-N batch). The math mirrors the formula in
// risk.RankExposures: severity weight × duration factor × blind
// multiplier. Callers receive the score and the breakdown together
// so the roadmap entry can populate ScoreBreakdown without a second
// pass over the same fields.
func (f *Finding) ComputeBaseScore() (float64, findings.ScoreBreakdown) {
	if f == nil {
		return 0, findings.ScoreBreakdown{}
	}
	base := f.ControlSeverity.Weight()
	daysBlind := f.Evidence.UnsafeDurationHours / 24.0
	durFactor := risk.DurationFactor(f.Evidence.UnsafeDurationHours)
	blindMult := risk.BlindMultiplier(daysBlind)
	score := float64(base) * durFactor * blindMult
	return score, findings.ScoreBreakdown{
		BaseScore:          base,
		DurationFactor:     durFactor,
		BlastMultiplier:    1.0,
		ExposureMultiplier: 1.0,
		BlindMultiplier:    blindMult,
		DaysBlind:          daysBlind,
	}
}

// PriorityAttributes packages the chain-membership + SLA-overdue
// state the rank renderer needs into a single struct so the priority
// entry construction site doesn't query four predicates and two
// accessors separately. Returned values mirror the originating
// Finding accessors:
//
//   - IsChainMember / ChainID / ChainSeverity come from
//     IsChainMember() and the PrimaryChain* accessors.
//   - SLABreached / OverdueHours come from IsOverdue() and
//     OverdueHours().
//
// Centralised here so a future enrichment field (e.g. chain
// confidence, SLA escalation severity) lands on the type, not at
// every priority-entry construction site.
type PriorityAttributes struct {
	IsChainMember bool
	ChainID       string
	ChainSeverity string
	SLABreached   bool
	OverdueHours  float64
	HasOverdue    bool
}

// PriorityAttributes returns the chain-membership and SLA overdue
// projections for use by the rank renderer. See PriorityAttributes
// for the contract.
func (f *Finding) PriorityAttributes() PriorityAttributes {
	if f == nil {
		return PriorityAttributes{}
	}
	out := PriorityAttributes{}
	if f.IsChainMember() {
		out.IsChainMember = true
		out.ChainID = f.PrimaryChainID()
		out.ChainSeverity = f.PrimaryChainSeverity()
	}
	if f.IsOverdue() {
		out.SLABreached = true
		if hours, ok := f.OverdueHours(); ok {
			out.OverdueHours = hours
			out.HasOverdue = true
		}
	}
	return out
}

// RiskContribution returns the per-finding contribution to an
// account-level risk score: severity weight × duration factor.
// Differs from ComputeBaseScore in that it omits the BlindMultiplier
// — consolidate's per-account roll-up uses the simpler formula so a
// long-blind finding doesn't dominate the account total. Centralised
// so consolidate's assessAccount loop stops re-deriving the (base ×
// dur) product inline.
func (f *Finding) RiskContribution() float64 {
	if f == nil {
		return 0
	}
	base := float64(f.ControlSeverity.Weight())
	dur := risk.DurationFactor(f.Evidence.UnsafeDurationHours)
	return base * dur
}

// IsOverdue reports whether the finding has breached SLA AND the
// overdue duration is recorded. Use this when the renderer or
// summary will dereference the overdue value; use IsAnyBreach for
// boolean-only rollups.
//
// The two-field check matters: a finding can be flagged breached
// without an overdue duration when the SLA evaluator runs in a
// degraded mode (no deadline configured). Treating the breach
// flag alone as "overdue" inflated counters in those cases.
//
// See IsCriticalSLABreach for the full SLA state vocabulary.
func (f *Finding) IsOverdue() bool {
	return f.slaBreached && f.slaOverdueHours != nil
}

// HasSLA reports whether an SLA deadline applies to this finding.
// The loosest predicate in the SLA vocabulary: says only that the
// evaluator attached a deadline, not that the deadline has been
// met or breached. Use for "is this finding under SLA tracking?"
// gating; use IsAnyBreach / IsOverdue for breach-state checks.
//
// See IsCriticalSLABreach for the full SLA state ladder.
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

// AddChainMembership appends a chain-membership entry to the
// finding. Centralised so the chain-attribution pass in
// app/eval/workflow stops mutating the slice directly — keeps the
// invariant ("entries are appended in chain-detection order, never
// reordered") on the type that owns the slice. A future change
// (deduplication, capacity reservation) lands one place.
func (f *Finding) AddChainMembership(entry ChainMembershipEntry) {
	if f == nil {
		return
	}
	f.ChainMembership = append(f.ChainMembership, entry)
}

// ChainMembershipEntries returns the chain-membership slice for
// adapter mapping. Returns nil when the finding does not
// participate in any chain so callers can branch on len(out) > 0
// without dereferencing a nil receiver.
func (f *Finding) ChainMembershipEntries() []ChainMembershipEntry {
	if f == nil {
		return nil
	}
	return f.ChainMembership
}

// HasExposure reports whether the finding carries the catalog's
// authored Exposure block. Replaces (f.Exposure != nil) probes.
func (f *Finding) HasExposure() bool {
	return f != nil && f.Exposure != nil
}

// ExposureType returns the catalog's exposure type as a string,
// or "" when no exposure block is present. Centralises the
// (f.Exposure != nil ? string(f.Exposure.Type) : "") cascade so
// callers stop reaching through the optional pointer.
func (f *Finding) ExposureType() string {
	if !f.HasExposure() {
		return ""
	}
	return string(f.Exposure.Type)
}

// PrincipalScopeString returns the principal-scope rendering
// expected by DTO / SARIF / telemetry surfaces, or "" when no
// exposure block is present.
func (f *Finding) PrincipalScopeString() string {
	if !f.HasExposure() {
		return ""
	}
	return f.Exposure.PrincipalScope.String()
}

// HasPostureDrift reports whether the finding carries
// recurrence-pattern data. Replaces (f.PostureDrift != nil) probes.
func (f *Finding) HasPostureDrift() bool {
	return f != nil && f.PostureDrift != nil
}

// PostureDriftPattern returns the catalog-emitted drift label, or
// the zero value when no posture-drift block is present.
func (f *Finding) PostureDriftPattern() DriftPattern {
	if !f.HasPostureDrift() {
		return ""
	}
	return f.PostureDrift.Pattern
}

// PostureDriftWindowCount returns the recurrence count from the
// drift block, or 0 when no posture-drift block is present.
func (f *Finding) PostureDriftWindowCount() int {
	if !f.HasPostureDrift() {
		return 0
	}
	return f.PostureDrift.ExposureWindowCount
}

// HasAlternatives reports whether the catalog declared
// alternative-tool mappings for the finding's control. Replaces
// (len(f.Alternatives) > 0) probes.
func (f *Finding) HasAlternatives() bool {
	return f != nil && len(f.Alternatives) > 0
}

// HasReachability reports whether the finding carries IAM-graph
// reachability context. Populated when the snapshot includes
// identity data and the reachability annotator has run; nil
// otherwise. Replaces (f.Reachability != nil) probes in the
// narrative builder, rank blast-radius scorer, and the public
// mirror converter.
func (f *Finding) HasReachability() bool {
	return f != nil && f.Reachability != nil
}

// HasClassification reports whether the finding carries a
// non-empty Classification tag (e.g. "state_assertion",
// "presence_check"). Replaces (f.Classification != "") probes in
// the SARIF properties-bag builder.
func (f *Finding) HasClassification() bool {
	return f != nil && f.Classification != ""
}

// HasScopeTags reports whether the finding carries any
// scope-tag annotations (e.g. "aws", "s3", "public-access").
// Replaces (len(f.ScopeTags) > 0) probes.
func (f *Finding) HasScopeTags() bool {
	return f != nil && len(f.ScopeTags) > 0
}

// HasEnrichedContext reports whether the finding carries
// analytical metadata beyond the bare control violation: a chain
// membership, a reasoning trace, alternative-tool mappings, a
// semantic classification tag, or scope tags. Renderers
// (currently the SARIF properties-bag emitter) gate the
// extended-context block on this single predicate so a future
// enrichment field (e.g. probability score, ontology mapping)
// is one edit on the Finding type rather than a 5-clause OR in
// every output adapter.
//
// Aligns with Stave's pipeline framing: a "raw" finding is just
// a rule failure; an "enriched" finding has been through the
// graph / ontology / chain layers and gained context. Callers
// asking the type "do you have enriched context?" no longer
// reconstruct that meaning from a multi-part disjunction at
// every site.
func (f *Finding) HasEnrichedContext() bool {
	return f.IsChainMember() ||
		f.HasReasoningTrace() ||
		f.HasAlternatives() ||
		f.HasClassification() ||
		f.HasScopeTags()
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
	switch {
	case f.IsOverdue():
		out.Breached = 1
		if h, ok := f.OverdueHours(); ok {
			out.OverdueHours = h
		}
	case f.IsAnyBreach():
		// Degraded-mode breach: the SLA flag is set but the
		// overdue-hours field is nil (snapshot lacks lifecycle
		// dates needed to compute remaining time). Counts as
		// breached, NOT within-SLA — the previous else branch
		// silently classified these as compliant.
		out.Breached = 1
	default:
		out.WithinSLA = 1
	}
	return out
}

// SeveritySortRank returns the sort key the JSON report renderer
// uses to order findings by descending severity. Critical → 0,
// High → 1, Medium → 2, Low → 3, Info → 4. Encapsulates the
// (SeverityCritical - ControlSeverity) arithmetic on the iota
// ordering so renderers stop reaching for the constant directly.
//
// A nil receiver returns 0 — the highest-priority bucket — so a
// degenerate / placeholder Finding sorts to the front rather than
// being buried under real Critical findings (the previous behaviour
// returned int(SeverityCritical) which is 5, sorting nil findings
// last).
func (f *Finding) SeveritySortRank() int {
	if f == nil {
		return 0
	}
	return int(policy.SeverityCritical - f.ControlSeverity)
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
func (f *Finding) MatchesOwner(allowed map[string]struct{}) bool {
	if f == nil || allowed == nil {
		return false
	}
	_, ok := allowed[f.OwnerKey()]
	return ok
}

// IsChainMember reports whether the finding contributed to one or
// more fired chains. Sorting and rendering paths use this to push
// chain participants ahead of single-control violations.
//
// Nil-safe: required because HasEnrichedContext calls this on
// possibly-nil receivers (the other predicates folded into the
// disjunction already nil-guard themselves).
func (f *Finding) IsChainMember() bool {
	if f == nil {
		return false
	}
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

// Exploitability classifies a finding's position in the attack graph.
type Exploitability string

const (
	// ExploitabilityExploitable means this finding participates in a
	// compound chain where all preconditions are present.
	ExploitabilityExploitable Exploitability = "exploitable"

	// ExploitabilityOneAway means this finding participates in a chain
	// that would fire if one currently-absent precondition appeared.
	ExploitabilityOneAway Exploitability = "one_away"

	// ExploitabilityReachable means the finding is true but not
	// connected to a complete or near-complete attack path.
	ExploitabilityReachable Exploitability = "reachable"
)

// DecidingLayer identifies which policy layer is responsible for a
// finding — i.e. which layer the operator should change to remediate.
type DecidingLayer string

const (
	LayerIdentityPolicy       DecidingLayer = "identity_policy"
	LayerTrustPolicy          DecidingLayer = "trust_policy"
	LayerSCPCeiling           DecidingLayer = "scp_ceiling"
	LayerPermissionBoundary   DecidingLayer = "permission_boundary"
	LayerResourcePolicy       DecidingLayer = "resource_control_policy"
	LayerCredentialManagement DecidingLayer = "credential_management" //nolint:gosec // domain enum, not a credential
	LayerFederation           DecidingLayer = "federation"
)

// NearMissEntry records that a finding is one control away from
// completing a compound chain.
type NearMissEntry struct {
	ChainID        kernel.ChainID   `json:"chain_id"`
	ChainSeverity  policy.Severity  `json:"chain_severity"`
	MissingControl kernel.ControlID `json:"missing_control"`
	Description    string           `json:"description"`
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
		Scope:              m.Scope,
		CorpusReference:    m.CorpusReference,
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
//
// Returns no error by design (matches AcknowledgedFinding.WriteDetails):
// the writer is a human-facing terminal renderer where partial-flush
// failures are recovered by the surrounding command-loop frame, and
// threading an error through every renderer call would force every
// caller to handle an error that ultimately gets logged once at the
// CLI boundary. Wire-format / contract-bearing output uses the
// marshaler paths in adapters/, which DO return errors.
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
