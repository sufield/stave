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
// audit, all observed assets and identities, the per-resource
// raw vector groups the solver composes, and the temporal facts
// that ground duration-based and recurrence-based reasoning.
//
// EvaluatedAt is the caller-supplied "now" — equal to the
// `--now` flag value or to the engine's clock — never the
// process wall clock.
//
// Iter L0: ResourceGroups REPLACES the deprecated
// EffectivePermissions slice. Stave no longer aggregates AWS
// evaluation semantics; the solver composes Policy ∪ ACL ∪ IAM
// minus PAB suppression in Z3 directly from the raw vectors
// inside each ResourceFactGroup. The Suppressed flag and
// EffectivePermissionFact type that lived here briefly are
// retired.
type Document struct {
	Controls       []ControlFact       `json:"controls"`
	Assets         []AssetFact         `json:"assets"`
	Identities     []IdentityFact      `json:"identities"`
	ResourceGroups []ResourceFactGroup `json:"resource_groups,omitempty"`
	Temporal       TemporalFacts       `json:"temporal"`
	EvaluatedAt    time.Time           `json:"evaluated_at"`
}

// ResourceFactGroup bundles every raw vector fact for a single
// resource (e.g., one S3 bucket) so the solver receives all
// inputs needed to compose the resource's effective access set
// in one place. Stave NEVER mixes vectors from different
// resources into one group; one bucket = one group.
//
// The four vector slices are mutually independent inputs. The
// solver applies AWS-evaluation semantics (Policy ∪ ACL ∪
// AttachedIAM with PAB suppression and explicit-deny
// precedence) symbolically; Stave does not pre-compute any of
// it.
type ResourceFactGroup struct {
	AssetID      string                      `json:"asset_id"`
	Vendor       string                      `json:"vendor"`
	ServiceArea  string                      `json:"service_area"`
	BucketPolicy []BucketPolicyStatementFact `json:"bucket_policy,omitempty"`
	ACLGrants    []ACLGrantFact              `json:"acl_grants,omitempty"`
	PAB          []PublicAccessBlockFact     `json:"pab,omitempty"`
	AttachedIAM  []IAMPolicyStatementFact    `json:"attached_iam,omitempty"`
	Source       SourceRef                   `json:"source"`
}

// TypedPrincipal is one decoded principal in a bucket-policy or
// IAM-policy statement. AWS principal blocks are polymorphic
// (string wildcard, AWS list, Service list, Federated list,
// CanonicalUser list); the extractor decomposes them into
// per-entry TypedPrincipal rows so the solver iterates a flat
// list rather than re-parsing AWS's polymorphism.
//
// IsPublic is the schema-typed flag for the AWS wildcard
// principal — strictly Value == "*" with Kind == "Wildcard".
// It is NOT a derived "this statement is public" inference;
// whether a statement actually grants public access depends
// on Effect, Condition, and other statements (solver work).
type TypedPrincipal struct {
	Kind     string `json:"kind"`
	Value    string `json:"value"`
	IsPublic bool   `json:"is_public,omitempty"`
}

// ConditionFact is one (operator, key, values) tuple from a
// statement's Condition block. Values are emitted verbatim;
// the solver decides what string patterns mean.
type ConditionFact struct {
	Operator string    `json:"operator"`
	Key      string    `json:"key"`
	Values   []string  `json:"values"`
	Source   SourceRef `json:"source"`
}

// BucketPolicyStatementFact is one statement of an S3 bucket
// policy, decoded into typed values. The fact carries every
// AWS-schema field the solver might consult: Effect, principal
// + not-principal, action + not-action, resource + not-resource,
// conditions. StatementIndex is the position in the original
// `Statement` array — stability of this index is part of the
// SourceRef contract.
type BucketPolicyStatementFact struct {
	StatementIndex int              `json:"statement_index"`
	Sid            string           `json:"sid,omitempty"`
	Effect         string           `json:"effect"`
	Principals     []TypedPrincipal `json:"principals,omitempty"`
	NotPrincipals  []TypedPrincipal `json:"not_principals,omitempty"`
	Actions        []string         `json:"actions,omitempty"`
	NotActions     []string         `json:"not_actions,omitempty"`
	Resources      []string         `json:"resources,omitempty"`
	NotResources   []string         `json:"not_resources,omitempty"`
	Conditions     []ConditionFact  `json:"conditions,omitempty"`
	Source         SourceRef        `json:"source"`
}

// ACLGrantFact is one ACL grant on an S3 bucket, decoded from
// the get-bucket-acl response. L4 wires this from the existing
// acl.ACLGrant produced by 4.0.1.
type ACLGrantFact struct {
	GranteeKind  string    `json:"grantee_kind"`
	GranteeURI   string    `json:"grantee_uri,omitempty"`
	GranteeID    string    `json:"grantee_id,omitempty"`
	GranteeEmail string    `json:"grantee_email,omitempty"`
	Permission   string    `json:"permission"`
	IsPublic     bool      `json:"is_public,omitempty"`
	IsAnyAuth    bool      `json:"is_any_auth,omitempty"`
	Source       SourceRef `json:"source"`
}

// PublicAccessBlockFact is one layer of S3 Public Access Block
// configuration (account-level or bucket-level). L3 fills in
// the four boolean flags. Stave emits one fact per layer; the
// solver composes them with logical OR.
type PublicAccessBlockFact struct {
	BlockPublicAcls       bool      `json:"block_public_acls"`
	IgnorePublicAcls      bool      `json:"ignore_public_acls"`
	BlockPublicPolicy     bool      `json:"block_public_policy"`
	RestrictPublicBuckets bool      `json:"restrict_public_buckets"`
	Source                SourceRef `json:"source"`
}

// IAMPolicyStatementFact is one IAM policy statement that may
// affect an S3 bucket's effective access. Same shape as
// BucketPolicyStatementFact plus AttachedTo (the principal the
// policy is attached to) and PolicyARN (managed-policy ARN, or
// empty for inline policies).
type IAMPolicyStatementFact struct {
	StatementIndex int              `json:"statement_index"`
	Sid            string           `json:"sid,omitempty"`
	Effect         string           `json:"effect"`
	Principals     []TypedPrincipal `json:"principals,omitempty"`
	NotPrincipals  []TypedPrincipal `json:"not_principals,omitempty"`
	Actions        []string         `json:"actions,omitempty"`
	NotActions     []string         `json:"not_actions,omitempty"`
	Resources      []string         `json:"resources,omitempty"`
	NotResources   []string         `json:"not_resources,omitempty"`
	Conditions     []ConditionFact  `json:"conditions,omitempty"`
	AttachedTo     *TypedPrincipal  `json:"attached_to,omitempty"`
	PolicyARN      string           `json:"policy_arn,omitempty"`
	Source         SourceRef        `json:"source"`
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
//
// HopType names the AWS primitive connecting the two roles.
// Iter 2 (gap-closure-2) values:
//
//	"assume_role"    — sts:AssumeRole and federated variants;
//	                   the only kind the pre-Iter-2 walker
//	                   produced.
//	"tag_mutation"   — ABAC privesc: principal can self-tag the
//	                   target role to satisfy a tag-conditional
//	                   trust policy, then assume.
//
// Empty / absent on the wire means "assume_role" for backward
// compatibility with pre-Iter-2 SIR documents.
type RoleHopFact struct {
	From         string `json:"from"`
	To           string `json:"to"`
	CrossAccount bool   `json:"cross_account,omitempty"`
	HopType      string `json:"hop_type,omitempty"`
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

	// ScheduledDeletionAt records the earliest scheduled-deletion
	// timestamp across the chain's hops, when the snapshot
	// indicates that one of the traversed identities is marked
	// for deletion at a known future time. Zero / absent means no
	// hop is scheduled for deletion. Iter 5 (TOCTOU): downstream
	// solvers use this annotation to surface "future ghost
	// reference" findings — chains that are reachable today but
	// will be stale once the deletion completes.
	ScheduledDeletionAt time.Time `json:"scheduled_deletion_at,omitempty"`
}

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

// PermissionFact is one (action, resource, condition*) tuple
// inside an identity's ValidityWindow. The Conditions slice
// reuses ConditionFact (defined alongside the L1 statement
// facts above).
type PermissionFact struct {
	Action     string          `json:"action"`
	Resource   string          `json:"resource"`
	Conditions []ConditionFact `json:"conditions,omitempty"`
	Source     SourceRef       `json:"source"`
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
