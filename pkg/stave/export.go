package stave

import (
	"context"
	"errors"
	"time"

	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/platform/providers/aws/iam"
	"github.com/sufield/stave/pkg/stave/internal/policyexport"
)

// ExportConfig configures a policy-data export run.
//
// SnapshotsDir is required and points at the same observation
// directory [Apply] reads. The export reuses the public
// observation loader, so any directory accepted by Apply is
// accepted here.
//
// AllowUnknownInput mirrors [Config.AllowUnknownInput] for callers
// extracting from sources that emit asset types Stave's catalog
// does not formally know about.
type ExportConfig struct {
	SnapshotsDir      string
	AllowUnknownInput bool

	// EffectivePermissionResolver computes the post-aggregation
	// permission set for every principal in each loaded
	// snapshot. nil leaves the resolver default — the AWS
	// implementation that wraps internal/platform/providers/aws/iam.
	// Pass a stub here for tests that need deterministic
	// per-principal grants without exercising the full IAM
	// resolution algorithm.
	EffectivePermissionResolver ports.EffectivePermissionResolver
}

// PolicyExport is the structured projection of a snapshot's
// resource-based and trust policies, plus the asset relationships
// observable from property references. The shape is solver-ready:
// no engine semantics are encoded, no controls are evaluated, no
// findings are produced — every field is a pure transformation of
// observation data into typed Go values.
//
// Today's surface covers the resource-policy paths Stave's
// extractors emit (S3 / Lambda / messaging / secrets), the KMS
// key policy path, IAM trust policies, and the
// (resource → KMS key, principal → role) edges those policies
// imply. New policy shapes (IAM managed/inline, SG/NACL) extend
// this struct directly when their wire format is standardised —
// the export is meant to grow by addition, not by reserving empty
// slots in advance.
type PolicyExport struct {
	GeneratedAt        time.Time
	ResourcePolicies   []PolicyDocument
	TrustPolicies      []TrustDocument
	KMSKeyPolicies     []PolicyDocument
	AssetRelationships []AssetEdge

	// EffectivePermissions is the post-aggregation permission set
	// computed by the [ports.EffectivePermissionResolver] the
	// caller wired into ExportConfig — one entry per
	// (principal, action, resource) tuple after SCP ceiling,
	// permission boundary, identity-based allows, and explicit
	// denies have been applied.
	//
	// Empty when no resolver was configured. The default
	// [ExportPolicies] path attaches the AWS resolver
	// automatically; advanced callers (custom providers, tests
	// that pin a stub) override via
	// [ExportConfig.EffectivePermissionResolver].
	//
	// Distinct from the raw policy documents above: those are
	// what the cloud said; this is what the cloud's own evaluator
	// would actually allow. A Z3 reachability query asking "can
	// principal X take action Y on resource Z?" reads this slice
	// directly instead of re-deriving the answer from raw
	// statements.
	EffectivePermissions []EffectivePermission
}

// EffectivePermission is one aggregated grant — the public alias
// for the port-level type so consumers don't need to pull the
// internal/core/ports import path.
type EffectivePermission = ports.EffectivePermission

// PolicyDocument is a parsed AWS-style policy document keyed to
// the asset that owns it. PolicyType disambiguates the source path
// ("s3_bucket", "kms_key", "lambda", "messaging", "secret",
// "iam_managed", "iam_inline") so consumers can branch on the
// document kind without re-parsing the asset properties.
type PolicyDocument = policyexport.PolicyDocument

// TrustDocument is an IAM role trust policy. Held separately from
// PolicyDocument so consumers can branch on document kind directly.
type TrustDocument = policyexport.TrustDocument

// PolicyStatement is the structured statement shape every AWS
// policy follows. NotPrincipals / NotActions / NotResources are
// surfaced separately so consumers can encode the negative-form
// semantics without re-walking the raw JSON.
type PolicyStatement = policyexport.PolicyStatement

// Condition pairs an AWS condition operator (e.g. "StringEquals",
// "ArnLike", "Bool") with a key (e.g. "aws:PrincipalOrgID") and
// the expected values. The wire format collapses entries with the
// same (operator, key) into a nested map; the export expands to
// one Condition per pair so consumers iterate flat.
type Condition = policyexport.Condition

// AssetEdge records a directional relationship between two assets
// observable in the snapshot. Relationship names the link shape:
//
//   - "encrypts_with" — resource → KMS key (from the encryption
//     block's key_arn / key_id reference).
//   - "assumes" — principal → IAM role (from the role's trust
//     policy's AWS:<arn> principals).
//
// External tools (Neo4j, Z3) consume the edge list to compute
// reachability without re-walking observation property bags.
type AssetEdge = policyexport.AssetEdge

// ExportPolicies loads the snapshots in cfg.SnapshotsDir and walks
// every asset and identity to produce a typed [PolicyExport].
// Equivalent to running the observation loader without invoking
// the evaluation pipeline — no controls, no findings, no SLA, just
// the structured policy data.
//
// Use this when an external tool (Z3 solver, Neo4j visualiser,
// custom reasoner) needs Stave's parsed policies but must not
// inherit Stave's evaluation semantics. The export carries no
// solver dependency: pkg/stave does not import Z3, does not link
// to it, and does not know it exists.
func ExportPolicies(ctx context.Context, cfg ExportConfig) (*PolicyExport, error) {
	if cfg.SnapshotsDir == "" {
		return nil, errors.New("stave.ExportPolicies: ExportConfig.SnapshotsDir is required")
	}
	resolver := cfg.EffectivePermissionResolver
	if resolver == nil {
		// Default to the AWS implementation. Other providers
		// register their own here when they ship one; for now
		// the only supported cloud is AWS, so the unconditional
		// default mirrors the rest of the export path's
		// AWS-only assumptions.
		resolver = iam.NewEffectivePermissionResolver()
	}
	r, err := policyexport.Run(ctx, policyexport.Config{
		SnapshotsDir:         cfg.SnapshotsDir,
		AllowUnknownInput:    cfg.AllowUnknownInput,
		EffectivePermissions: resolver,
	})
	if err != nil {
		return nil, err
	}
	return &PolicyExport{
		GeneratedAt:          r.GeneratedAt,
		ResourcePolicies:     r.ResourcePolicies,
		TrustPolicies:        r.TrustPolicies,
		KMSKeyPolicies:       r.KMSKeyPolicies,
		AssetRelationships:   r.AssetRelationships,
		EffectivePermissions: r.EffectivePermissions,
	}, nil
}
