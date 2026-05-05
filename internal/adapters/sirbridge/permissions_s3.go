package sirbridge

import (
	"strconv"
	"strings"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/sir"
	"github.com/sufield/stave/internal/platform/providers/aws/compliance"
	"github.com/sufield/stave/internal/platform/providers/aws/s3/policy"
)

// AWSS3PermissionAggregator implements sir.PermissionAggregator
// for AWS S3 buckets per docs/aggregation_decisions.md S3.2:
// "Effective public exposure (Bucket Policy ∩ ACL ∩ BPA ∩
// Ownership)". The aggregator owns the AWS-semantic combination
// of these vectors so downstream Z3 reasoning operates over the
// already-aggregated effective access set.
//
// Coverage in this iteration:
//   - Bucket Policy: walked via s3/policy.Parse + statement-level
//     methods (PrincipalScope, ConditionAnalysis, ResolveActions).
//   - BPA: read via compliance.ParseS3Properties; bucket-level
//     BlockPublicPolicy / RestrictPublicBuckets and account-level
//     full-block both suppress public statements.
//   - Ownership: ACLsDisabled (BucketOwnerEnforced) is recorded as
//     a contributing source on the asset's emitted facts.
//   - ACL grants: NOT yet aggregated. No production code today
//     extracts ACL grants from the snapshot's asset.Properties
//     (the s3/acl package is reachable only via cmd/inspect/acl
//     which reads grants from a separate file). Adding that
//     extraction is its own work item; until it lands, the
//     aggregator's effective set is "policy minus BPA suppression"
//     plus an "acl_unhydrated" annotation on each fact's
//     ContributingSources so a downstream consumer can tell apart
//     "ACL was checked and was empty" from "ACL was not checked."
type AWSS3PermissionAggregator struct{}

// NewAWSS3PermissionAggregator returns a ready-to-use aggregator.
// No configuration needed — the aggregation rule is fixed by AWS
// S3's evaluation semantics.
func NewAWSS3PermissionAggregator() *AWSS3PermissionAggregator {
	return &AWSS3PermissionAggregator{}
}

// Aggregate satisfies sir.PermissionAggregator. For each S3
// bucket across the snapshot set the aggregator emits zero or
// more EffectivePermissionFact rows: one per (bucket, statement)
// pair where the statement survives BPA suppression. Ownership
// (ACLsDisabled) and BPA flags appear as ContributingSources so
// the solver can introspect which AWS-side primitives shaped the
// final fact.
func (a *AWSS3PermissionAggregator) Aggregate(snapshots []asset.Snapshot, _ time.Time) ([]sir.EffectivePermissionFact, error) {
	// Track per-asset first/last seen so emitted facts carry the
	// observation grid without repeating the snapshot scan in
	// each method.
	type bucketTimes struct {
		first time.Time
		last  time.Time
	}
	timesByID := make(map[asset.ID]bucketTimes)
	bucketsByID := make(map[asset.ID]asset.Asset)

	for _, snap := range snapshots {
		ts := snap.CapturedAt
		for _, a := range snap.Assets {
			if !isS3BucketType(a.Type) {
				continue
			}
			bucketsByID[a.ID] = a
			t := timesByID[a.ID]
			if !ts.IsZero() && (t.first.IsZero() || ts.Before(t.first)) {
				t.first = ts
			}
			if !ts.IsZero() && ts.After(t.last) {
				t.last = ts
			}
			timesByID[a.ID] = t
		}
	}

	out := make([]sir.EffectivePermissionFact, 0)
	for id, bucket := range bucketsByID {
		props := compliance.ParseS3Properties(bucket)
		facts := factsForBucket(string(id), props, timesByID[id].first, timesByID[id].last)
		out = append(out, facts...)
	}
	return out, nil
}

// isS3BucketType matches the wire-format asset type stave's
// extractors emit for S3 buckets. Centralised here rather than
// reusing compliance.isS3Bucket (unexported) so the aggregator
// stays free of compliance-internal coupling beyond the typed
// S3Properties shape.
func isS3BucketType(t kernel.AssetType) bool {
	return string(t) == "aws_s3_bucket"
}

// factsForBucket walks a single bucket's policy statements and
// emits the surviving effective-permission facts. BPA suppression
// is applied per-statement; the suppression decisions are
// recorded as ContributingSources entries (so a future
// "explain why this fact exists" tooling can render the AWS
// reasoning chain without re-deriving it).
func factsForBucket(bucketID string, props compliance.S3Properties, validFrom, validUntil time.Time) []sir.EffectivePermissionFact {
	if props.PolicyJSON == "" {
		return nil
	}
	doc, err := policy.Parse(props.PolicyJSON)
	if err != nil || doc == nil {
		return nil
	}
	stmts := doc.Statements()
	if len(stmts) == 0 {
		return nil
	}

	bpaFullyBlocks := props.Controls.IsPublicAccessFullyBlocked() ||
		props.Controls.AccountPublicAccessFullyBlocked
	bpaBlocksPolicy := props.Controls.PublicAccessBlock.Present &&
		(props.Controls.PublicAccessBlock.BlockPublicPolicy ||
			props.Controls.PublicAccessBlock.RestrictPublicBuckets)

	var out []sir.EffectivePermissionFact
	for i := range stmts {
		stmt := &stmts[i]
		if !stmt.Effect.IsAllow() || !stmt.GrantsAccess() {
			continue
		}

		publicly := stmt.IsPubliclyExposed()

		// BPA suppression (S3.2 layered veto): public statements
		// are dropped when BPA fully blocks public access at the
		// bucket level OR the account-level BPA fully blocks AND
		// no bucket-level escape exists. The compliance package's
		// IsPublicAccessFullyBlocked is the canonical predicate.
		if publicly && (bpaFullyBlocks || bpaBlocksPolicy) {
			continue
		}

		fact := sir.EffectivePermissionFact{
			AssetID:             bucketID,
			PrincipalID:         principalLabel(&stmt.Principal),
			Actions:             append([]string{}, []string(stmt.Action)...),
			AllowedFromNetwork:  networkScopesFor(stmt),
			ContributingSources: contributingSourcesFor(bucketID, i, stmt, props),
			ValidFrom:           validFrom,
			ValidUntil:          validUntil,
		}
		out = append(out, fact)
	}
	return out
}

// principalLabel collapses a NormalizedPrincipal into the single
// canonical principal-id string the SIR exports. Wildcard wins
// because once a public grant exists the more-specific entries
// don't change reachability. For non-wildcard statements the
// label joins all concrete ARN-class entries with " | "; the
// solver introspects the original statement via the SourceRef
// when granular per-principal modelling is required.
func principalLabel(p *policy.NormalizedPrincipal) string {
	if p.Wildcard {
		return "*"
	}
	parts := []string{}
	parts = append(parts, p.AWSARNs...)
	for _, svc := range p.Services {
		parts = append(parts, "service:"+svc)
	}
	for _, fed := range p.Federated {
		parts = append(parts, "federated:"+fed)
	}
	for _, cu := range p.CanonicalUsers {
		parts = append(parts, "canonical:"+cu)
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " | ")
}

// networkScopesFor returns the SIR-vocabulary network-scope
// labels for the statement's effective reachability set. Maps
// the kernel.NetworkScope enum surfaced by the existing
// ConditionAnalysis to the SIR's stable string vocabulary.
func networkScopesFor(stmt *policy.Statement) []sir.NetworkScope {
	cond := stmt.ConditionAnalysis()
	if !cond.IsNetworkScoped() {
		return []sir.NetworkScope{sir.NetworkScope("public")}
	}
	scope := cond.ResolveNetworkScope()
	if label := scope.String(); label != "" {
		return []sir.NetworkScope{sir.NetworkScope(label)}
	}
	return nil
}

// contributingSourcesFor names every primitive that survived the
// aggregation for one statement: the policy statement itself,
// plus BPA / ownership flags that shaped the outcome.
//
// The "acl_unhydrated" entry is the honest signal that ACL
// grants were not part of the input — not that they were checked
// and found empty. A future pass that wires ACL extraction will
// replace this entry with concrete acl-grant SourceRefs.
func contributingSourcesFor(bucketID string, statementIndex int, stmt *policy.Statement, props compliance.S3Properties) []sir.SourceRef {
	out := []sir.SourceRef{
		{
			Kind: "statement",
			ID:   bucketID,
			Path: []string{"BucketPolicy", strconv.Itoa(statementIndex), statementLabel(stmt, statementIndex)},
		},
	}
	if props.ACLsDisabled() {
		out = append(out, sir.SourceRef{
			Kind: "ownership",
			ID:   bucketID,
			Path: []string{"BucketOwnerEnforced"},
		})
	} else {
		out = append(out, sir.SourceRef{
			Kind: "acl_unhydrated",
			ID:   bucketID,
			Path: []string{"acl_extraction_pending"},
		})
	}
	if props.Controls.PublicAccessBlock.Present {
		out = append(out, sir.SourceRef{
			Kind: "bpa",
			ID:   bucketID,
			Path: []string{"public_access_block", bpaShape(props.Controls.PublicAccessBlock)},
		})
	}
	return out
}

// statementLabel returns the statement's Sid when present (the
// human-meaningful tag policies authors use) or a stable index
// fallback. Keeps the SourceRef path human-readable for the
// solver / explainer without leaking ambient information.
func statementLabel(stmt *policy.Statement, index int) string {
	if stmt.Sid != "" {
		return stmt.Sid
	}
	return "idx:" + strconv.Itoa(index)
}

// bpaShape encodes the four BPA flags as a stable wire-format
// string (e.g. "1101") so the SIR's ContributingSources path
// captures the exact suppression configuration without
// fan-rolling the four flags into separate refs.
func bpaShape(b compliance.S3BlockPublicAccessConfig) string {
	bit := func(v bool) byte {
		if v {
			return '1'
		}
		return '0'
	}
	return string([]byte{
		bit(b.BlockPublicACLs),
		bit(b.IgnorePublicACLs),
		bit(b.BlockPublicPolicy),
		bit(b.RestrictPublicBuckets),
	})
}
