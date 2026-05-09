package ports

import "github.com/sufield/stave/internal/core/asset"

// EffectivePermissionResolver computes the post-aggregation
// permission set for every principal in a snapshot. A principal's
// effective permissions are the result of applying SCP ceiling,
// permission boundary ceiling, identity-based allows, and
// explicit denies in the AWS evaluation order — the same
// computation `iam.Resolve` performs for the nep CLI, surfaced
// here as a port so pkg/stave's PolicyExport can consume it
// without importing provider-internal code.
//
// Implementations are pure functions: same snapshot in, same
// permission set out, no I/O. The AWS implementation lives in
// internal/platform/providers/aws/iam (next to the resolver it
// wraps); other providers register their own implementation when
// they ship one.
//
// Returning a non-nil empty slice signals "the snapshot was
// processable but the principal set is empty" — distinct from
// returning nil + error which signals "could not process". Both
// callers and adapters should follow this convention so
// downstream consumers can distinguish the two.
type EffectivePermissionResolver interface {
	// ResolveSnapshot walks every principal in the snapshot and
	// returns one entry per (principal, action, resource) tuple.
	// Order is deterministic — implementations sort by
	// (PrincipalID, Action, Resource) so the same snapshot
	// produces byte-identical output across runs.
	ResolveSnapshot(snap *asset.Snapshot) []EffectivePermission
}

// EffectivePermission is one (principal, action, resource) tuple
// produced after the AWS policy-aggregation algorithm runs over
// SCP ceiling, permission boundary, identity-based allows, and
// explicit denies. The shape is intentionally provider-neutral —
// the field set is what every IAM-shaped resolver can produce.
//
// Source classifies which layer granted the permission:
//
//	"identity_policy" — managed / inline / group policy
//	"resource_policy" — bucket policy, KMS key policy, etc.
//	"compound"        — required across multiple layers
//
// PolicyARN names the document that ultimately granted the
// action — useful for tracing a finding back to a specific
// statement. Conditions is a string-formatted summary of any
// scope conditions on the grant ("StringEquals:aws:PrincipalOrgID=o-...");
// nil for unconditioned grants.
type EffectivePermission struct {
	PrincipalID string   `json:"principal_id"`
	Action      string   `json:"action"`
	Resource    string   `json:"resource"`
	Source      string   `json:"source"`
	PolicyARN   string   `json:"policy_arn,omitempty"`
	Conditions  []string `json:"conditions,omitempty"`
}
