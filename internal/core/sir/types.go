// Package sir defines the Stave Intermediate Representation (SIR):
// the canonical, vendor-neutral, platform-neutral fact set that an
// external solver (Z3) consumes to discharge compound risk.
//
// The package is the contract between Stave's evaluation engine
// (Librarian — collects, normalizes, aggregates) and an external
// proof system (Judge — does compound logic). It deliberately
// excludes any infrastructure noise: no file paths, no git metadata,
// no tool versions, no source filenames, no auto-stamped run
// timestamps. Every fact is a domain value sourced from inputs the
// caller already trusts.
//
// Hexagonal boundary: this package depends only on
// internal/core/controldef, internal/core/asset, internal/core/kernel,
// and internal/core/predicate (a sibling core package whose types
// the SIR translates to plain strings before storage). Platform
// adapters (AWS, GCP) feed the builder via injected aggregator
// interfaces; the SIR itself never imports an adapter.
package sir

import "time"

// Document is the root SIR value. A single Document represents the
// complete fact set for one evaluation run: all controls under
// audit, all observed assets and identities, the effective
// permission graph derived from policy aggregation, and the
// temporal facts that ground duration-based and recurrence-based
// reasoning. EvaluatedAt is the caller-supplied "now" — equal to
// the `--now` flag value or to the engine's clock — never
// the process wall clock.
type Document struct {
	Controls             []ControlFact             `json:"controls"`
	Assets               []AssetFact               `json:"assets"`
	Identities           []IdentityFact            `json:"identities"`
	EffectivePermissions []EffectivePermissionFact `json:"effective_permissions"`
	Temporal             TemporalFacts             `json:"temporal"`
	EvaluatedAt          time.Time                 `json:"evaluated_at"`
}

// SourceRef is a stable pointer back into the SIR's input. Kind
// names the input category ("control", "asset", "identity",
// "statement"); ID is the within-kind identifier; Path is the
// optional structural breadcrumb inside that input (e.g.
// ["unsafe_predicate","any","0"] for a single rule). The triple is
// human-readable but deterministic — the same fact regenerated on
// the same inputs yields byte-identical SourceRef values. SourceRef
// must NEVER carry file paths, line numbers, or other ambient
// filesystem coordinates; consumers that need to re-anchor a fact
// to a YAML file do so via the (Kind, ID) lookup against the
// original control/observation set, not via this struct.
type SourceRef struct {
	Kind string   `json:"kind"`
	ID   string   `json:"id"`
	Path []string `json:"path,omitempty"`
}

// IsEmpty reports whether the ref has no content. Used by tests
// that assert every fact carries a non-empty SourceRef.
func (s SourceRef) IsEmpty() bool {
	return s.Kind == "" && s.ID == "" && len(s.Path) == 0
}

// ControlFact is the SIR view of one control definition. Predicate
// captures the unsafe-predicate logic tree as an operator-neutral
// nested structure; ThresholdHours captures the duration gate
// (when present) for unsafe_duration controls.
//
// IntentRationale and ForbiddenState are the Iter 5.1 additions
// that move controls from "field checks" to "invariant
// enforcement". IntentRationale is human-authored prose stating
// WHY the control exists; an external solver / AI agent uses it
// to reason about whether a finding actually matters in the
// system's broader security model. ForbiddenState is a logical
// invariant that must NEVER be satisfied (distinct from the
// unsafe-predicate, which fires per-asset on match) — solver-side
// reasoning treats it as a hard constraint independent of the
// per-asset evaluation outcome.
type ControlFact struct {
	ID              string         `json:"id"`
	Type            string         `json:"type"`
	Severity        string         `json:"severity"`
	Predicate       PredicateFact  `json:"predicate"`
	ThresholdHours  *float64       `json:"threshold_hours,omitempty"`
	IntentRationale string         `json:"intent_rationale,omitempty"`
	ForbiddenState  *PredicateFact `json:"forbidden_state,omitempty"`
	Source          SourceRef      `json:"source"`
}

// PredicateFact is one node in the nested predicate tree. Logic is
// "any" or "all"; Rules are the child rules (each a leaf field/op
// pair or a nested PredicateFact).
type PredicateFact struct {
	Logic string     `json:"logic"`
	Rules []RuleFact `json:"rules"`
}

// RuleFact is one rule inside a predicate. Either Field/Operator/
// Value is set (a leaf field comparison) or Nested is set (a child
// predicate); the two forms are mutually exclusive but the
// distinction is encoded by which fields are populated rather than
// by an explicit tag, so SIR consumers can introspect both
// uniformly.
type RuleFact struct {
	Field    string         `json:"field,omitempty"`
	Operator string         `json:"operator,omitempty"`
	Value    any            `json:"value,omitempty"`
	Nested   *PredicateFact `json:"nested,omitempty"`
	Source   SourceRef      `json:"source"`
}

// AssetFact is the SIR view of one observed asset. Properties is
// the predicate-evaluable property bag (carried over from
// asset.Asset.Properties); the SIR does not interpret it, but
// downstream solvers may. Lifecycle (when populated) carries the
// asset's existence boundary across observations — provisioned/
// decommissioned transitions and first/last seen timestamps —
// so the Z3 Judge can reason about whether an asset existed at a
// given moment without rebuilding the temporal grid.
type AssetFact struct {
	ID         string              `json:"id"`
	Type       string              `json:"type"`
	Vendor     string              `json:"vendor"`
	Properties map[string]any      `json:"properties,omitempty"`
	Lifecycle  *AssetLifecycleFact `json:"lifecycle,omitempty"`
	Source     SourceRef           `json:"source"`
}

// AssetLifecycleFact captures an asset's existence boundary across
// the observation set. Provisioned is true when the most recent
// snapshot pair shows the asset newly appeared; Decommissioned is
// true when it disappeared. FirstSeen / LastSeen are the
// observation timestamps at the edges of the asset's known
// lifetime — the solver uses these to gate "was this asset live
// during exposure window W" queries without consulting the raw
// snapshot list.
type AssetLifecycleFact struct {
	Provisioned    bool      `json:"provisioned,omitempty"`
	Decommissioned bool      `json:"decommissioned,omitempty"`
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
}

// IdentityFact is the SIR view of one IAM identity. Validity is
// the temporal sequence of windows during which the identity held
// the named permissions. RoleChains carries the transitive
// sts:AssumeRole paths reachable from this principal — populated
// from the platform-side role-chain resolver via RoleChainSource.
// An identity with no validity windows is observed but exerts no
// permissions on any asset.
type IdentityFact struct {
	PrincipalID string           `json:"principal_id"`
	Validity    []ValidityWindow `json:"validity,omitempty"`
	RoleChains  []RoleChainFact  `json:"role_chains,omitempty"`
	Source      SourceRef        `json:"source"`
}

// RoleHopFact is one step in a transitive role-assumption path.
// CrossAccount is true when the target ARN's account differs from
// the source's — the AWS legal-boundary edge that the Z3 Judge
// reasons over to detect privilege escalation across accounts.
type RoleHopFact struct {
	From         string `json:"from"`
	To           string `json:"to"`
	CrossAccount bool   `json:"cross_account,omitempty"`
}

// RoleChainFact is a sequence of one or more RoleHopFact steps
// terminating at FinalRoleARN. TransitiveLevel labels the privilege
// classification of the final role (matches kernel privilege
// vocabulary: "admin", "elevated", "standard", "limited", "none").
// TerminationReason names why the resolver stopped extending the
// chain (e.g. "normal", "max_depth", "cycle", "not_in_snapshot")
// so the solver can distinguish a fully-explored path from one
// truncated by safety caps.
type RoleChainFact struct {
	Hops              []RoleHopFact `json:"hops"`
	FinalRoleARN      string        `json:"final_role_arn"`
	TransitiveLevel   string        `json:"transitive_level,omitempty"`
	TerminationReason string        `json:"termination_reason,omitempty"`
}

// EffectivePermissionFact is the SIR's aggregated permission edge:
// "principal P is permitted to perform Actions on AssetID, valid
// from ValidFrom to ValidUntil, reachable from these network
// scopes, with the listed contributing policy statements." Compound
// risk reasoning operates over this fact set rather than rederiving
// the union/intersection at solve time.
type EffectivePermissionFact struct {
	AssetID             string         `json:"asset_id"`
	PrincipalID         string         `json:"principal_id"`
	Actions             []string       `json:"actions"`
	AllowedFromNetwork  []NetworkScope `json:"allowed_from_network,omitempty"`
	ContributingSources []SourceRef    `json:"contributing_sources"`
	ValidFrom           time.Time      `json:"valid_from"`
	ValidUntil          time.Time      `json:"valid_until"`
}

// NetworkScope is the SIR's network-reachability label. Mirrors
// kernel.NetworkScope but is stored as a string so the SIR remains
// representation-stable across kernel iota reorderings.
type NetworkScope string

// TemporalFacts captures the time grid the SIR is grounded on:
// every captured snapshot timestamp (Observations) and every
// inferred exposure window (Windows). Compound checks that gate on
// "for at least N hours" or "during gap" reason against this
// structure rather than rederiving it.
type TemporalFacts struct {
	Observations []time.Time      `json:"observations"`
	Windows      []ExposureWindow `json:"windows"`
}

// ValidityWindow names a time interval during which a principal
// held the listed Permissions under the given scope/boundary
// labels. PrincipalScope and TrustBoundary are stringified
// kernel labels so the SIR does not ride the kernel's iota
// numbering.
type ValidityWindow struct {
	From           time.Time        `json:"from"`
	Until          time.Time        `json:"until"`
	PrincipalScope string           `json:"principal_scope"`
	NetworkScope   string           `json:"network_scope"`
	TrustBoundary  string           `json:"trust_boundary"`
	Permissions    []PermissionFact `json:"permissions,omitempty"`
	Source         SourceRef        `json:"source"`
}

// PermissionFact is one (action, resource, condition*) tuple.
type PermissionFact struct {
	Action     string          `json:"action"`
	Resource   string          `json:"resource"`
	Conditions []ConditionFact `json:"conditions,omitempty"`
	Source     SourceRef       `json:"source"`
}

// ConditionFact mirrors AWS's (Operator, Key, Values) condition
// triple but is vendor-neutral; GCP/Azure equivalents map onto the
// same shape at adapter time.
type ConditionFact struct {
	Operator string   `json:"operator"`
	Key      string   `json:"key"`
	Values   []string `json:"values"`
}

// ExposureWindow ties an asset to a time interval in which one or
// more controls' unsafe predicates matched. ContributingControls
// is the sorted set of control IDs whose predicate fired during
// the window — Z3 uses this to grade compound exposure across
// overlapping single-control windows.
type ExposureWindow struct {
	AssetID                string    `json:"asset_id"`
	Start                  time.Time `json:"start"`
	End                    time.Time `json:"end"`
	UnsafePredicateMatched bool      `json:"unsafe_predicate_matched"`
	ContributingControls   []string  `json:"contributing_controls"`
}

// CoverageGap names a time interval in which an asset was not
// observed at all (no snapshot covered it). Distinct from
// ExposureWindow: a gap is "we don't know", an exposure is "we
// observed unsafe state". Z3 uses gaps to decline to grade
// compound risk where evidence is missing — the Librarian/Judge
// split forbids the solver from treating gaps as either safe or
// unsafe.
type CoverageGap struct {
	AssetID string    `json:"asset_id"`
	Start   time.Time `json:"start"`
	End     time.Time `json:"end"`
	Reason  string    `json:"reason"`
}
