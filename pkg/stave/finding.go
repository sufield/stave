package stave

import (
	"time"

	"github.com/sufield/stave/internal/core/evaluation"
)

// Finding is a per-(control, asset) violation record.
//
// This is a trimmed view of the engine's internal finding shape.
// Fields that are CLI-adapter-specific (owner routing, SLA overlay
// fields, chain membership annotations, reachability context) or
// not yet earned through consumer evidence are omitted. Add them
// here when a consumer demonstrates a concrete need.
type Finding struct {
	// FindingID is a stable fingerprint over (control, asset).
	FindingID FindingID

	// ControlID identifies the fired control.
	ControlID ControlID

	// ControlName is the control's human-readable name.
	ControlName string

	// AssetID identifies the failing asset.
	AssetID AssetID

	// AssetType categorizes the failing asset.
	AssetType AssetType

	// Severity is the control's declared severity.
	Severity Severity

	// Classification marks the control's semantic role. Consumers
	// filtering "is this asset actually in the unsafe state?"
	// select [StateAssertion]; absence and parameterized checks
	// answer different questions and belong in separate buckets.
	Classification Classification

	// ScopeTags carries the control's scope_tags field. In
	// practice tags like "aws" or "s3" — the catalog is growing
	// more discriminating tags (e.g. "public-access") over time.
	ScopeTags []ScopeTag

	// ControlCompliance maps framework identifiers (e.g. "hipaa",
	// "soc2", "pci") to the specific citation the control
	// satisfies. Empty when the control declares no framework
	// mappings.
	ControlCompliance map[string]string

	// Remediation is the guidance the catalog authored for this
	// control. Zero value means the control declared no custom
	// remediation; the engine falls back to class-based defaults.
	Remediation Remediation

	// ReasoningTrace lists the predicate clauses the engine
	// evaluated to produce this finding, paired with the observed
	// values from the snapshot. Useful for explaining why a
	// finding fired. Also the backing data for the OBSERVED
	// section when adopters render the full triage chain.
	ReasoningTrace []MatchedClause

	// Defect / Infection / Failure carry the authored triage
	// chain from Andreas Zeller's Why Programs Fail, applied to
	// cloud misconfigurations. Copied from the control's YAML
	// metadata at evaluation time. Empty when the control hasn't
	// been authored for the failure-theory chain yet; consumer
	// rendering should skip empty sections rather than emit
	// placeholders.
	Defect    string
	Infection string
	Failure   string

	// Delta is the mechanically-derived set of fix paths. Each
	// DeltaPath is an independent change that eliminates this
	// finding. For AND predicates, any single path suffices. Nil
	// when derivation is not possible.
	Delta []DeltaPath

	// ChainMembership lists the compound-risk chains this finding
	// participates in. Empty when no chain's escalation threshold
	// was met OR when the library was run without chain definitions
	// loaded. See Assessment.ChainFindings for the top-level chain
	// entries referenced by ChainID.
	ChainMembership []ChainMembershipEntry

	// ChainBonus is the ExposureScore multiplier applied to this
	// finding by virtue of its chain membership: 1.0× for findings
	// on 0 chains, 1.5× for 1 chain, 2.0× for 2+ chains. Populated
	// by the engine's ranking pass. Useful when rendering scores
	// with provenance (e.g. "ExposureScore: 7.6 (2.0× chain
	// bonus)"). Defaults to 1.0 for findings not enrolled in any
	// chain.
	ChainBonus float64

	// ExposureScore is the priority score the engine assigned
	// after risk enrichment. Higher scores are more urgent.
	// Incorporates ChainBonus; sort findings by ExposureScore
	// descending to surface chain-member findings first.
	ExposureScore float64

	// Reachability carries IAM-graph context for this finding —
	// populated when the snapshot includes identity data and the
	// reachability annotator has run. Nil when no IAM context was
	// available. Use [Reachability.BlastRadiusScore] to rank
	// findings by their reachable-principal blast radius.
	Reachability *Reachability

	// SLABreached marks the finding as past its SLA deadline. Set
	// only when [Config.SLAConfig] is provided. Use together with
	// SLAOverdueHours to render breach context.
	SLABreached bool

	// SLADeadlineHours is the deadline in hours the engine applied
	// for this finding's severity. Nil when no SLA config was set
	// or no deadline was defined for the severity.
	SLADeadlineHours *float64

	// SLAOverdueHours is the dwell-time excess past the deadline.
	// Nil unless SLABreached.
	SLAOverdueHours *float64

	// SLAEscalatedSeverity carries the post-escalation severity
	// when the finding has been overdue for a multiple of its
	// deadline. Empty when no escalation applied.
	SLAEscalatedSeverity Severity

	// FirstUnsafeAt is the snapshot timestamp at which the engine
	// first observed this asset in an unsafe state. Zero-valued
	// when the engine hasn't computed lifecycle data (typically
	// when only a single snapshot was loaded). Mirrors the
	// internal Evidence.FirstUnsafeAt field; surfaced here so
	// solver-facing exports (GraphExport.FindingNode) can reason
	// about exposure dwell time without re-reading evaluation
	// internals.
	FirstUnsafeAt time.Time

	// LastSeenUnsafeAt is the snapshot timestamp at which the
	// engine most recently observed the asset still in an unsafe
	// state. Zero when no lifecycle data is available. Equal to
	// FirstUnsafeAt when only one unsafe snapshot was observed.
	LastSeenUnsafeAt time.Time

	// UnsafeDurationHours is the elapsed time (in hours) between
	// FirstUnsafeAt and the evaluation's `now`. Zero when no
	// lifecycle data is available. The same value the engine
	// uses to compare against `--max-unsafe`.
	UnsafeDurationHours float64

	// ContributingFactIDs lists the SIR fact_ids that describe the
	// configuration properties of this finding's asset. Use these
	// to grep from a CEL finding back to the specific JSONL triples
	// and SMT-LIB assertions emitted by `stave export-sir`, closing
	// the trace from finding → fact → property → engine verdict.
	//
	// Populated when the apply pipeline can build a SIR document
	// alongside the evaluation report. Empty when SIR-extraction
	// was skipped (the field is omitempty in JSON output, so
	// downstream consumers that ignore it see no schema change).
	//
	// Today the correlation key is asset_id — every fact whose
	// Subject equals AssetID is included, regardless of which CEL
	// predicate referenced which property. A future iteration may
	// narrow the set to facts whose property_path matches the
	// control's predicate references.
	ContributingFactIDs []string `json:"contributing_fact_ids,omitempty"`
}

// HasTemporalEvidence reports whether the finding carries any
// historical context — non-zero FirstUnsafeAt / LastSeenUnsafeAt,
// or a positive UnsafeDurationHours. False means the finding is
// a single point-in-time observation with no dwell-time data.
//
// Centralising the zero-check here lets export builders (and
// downstream solver code reasoning about transient vs persistent
// findings) ask the high-level question "is this lifecycle worth
// reporting?" rather than checking three fields individually.
// Adding a new temporal field later is a one-line update here
// instead of a hunt across every consumer.
//
// Value receiver to match the existing Frameworks() convention on
// this type — recvcheck flags mixed receivers.
func (f Finding) HasTemporalEvidence() bool {
	return !f.FirstUnsafeAt.IsZero() ||
		!f.LastSeenUnsafeAt.IsZero() ||
		f.UnsafeDurationHours > 0
}

// Reachability is the IAM-graph context for a finding. Carries the
// counts the blast-radius scorer used and the highest-privilege
// principal that can reach this asset. Mirrored from the internal
// shape so the public surface stays stable across engine refactors.
type Reachability struct {
	TotalReachablePrincipals   int
	PrivilegedPrincipalCount   int
	HighestPrivilegePrincipal  string
	ExternalPrincipalReachable bool
	BlastRadiusScore           float64
}

// MatchedClause is one predicate leaf clause evaluated against a
// snapshot. Aliased from the internal evaluation package.
type MatchedClause = evaluation.MatchedClause

// DeltaPath represents one independent fix that eliminates a finding.
type DeltaPath struct {
	PropertyLabel string // human-readable property name
	PropertyPath  string // raw observation path
	CurrentValue  string // observed value from snapshot
	FixAction     string // change needed to eliminate finding
}

// Remediation is the catalog-authored remediation guidance for a
// control. The fields are copied from the control's RemediationSpec
// in the YAML.
type Remediation struct {
	// Description is a brief human-readable summary.
	Description string

	// Action is the remediation text itself — either a
	// parameterized CLI command (e.g., "aws s3api put-bucket-acl ...")
	// when the catalog authored an executable fix, or prose when
	// the fix is advisory. Consumers detecting "do we have an
	// actionable command?" check whether this starts with a
	// known tool prefix.
	Action string

	// Example shows a concrete usage, when the catalog declared
	// one.
	Example string
}
