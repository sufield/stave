package sirbridge

import (
	"fmt"
	"strconv"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/sir"
	"github.com/sufield/stave/internal/platform/providers/aws/s3/acl"
)

// AWSS3FactGrouper assembles per-bucket ResourceFactGroup rows
// for the SIR. It is the L4 replacement for the retired
// AWSS3PermissionAggregator: pure pass-through, zero
// content-based logic. The grouper calls four extractors
// (L1 / 4.0.1 / L3 / L2) and bundles their outputs.
//
// Iter L4 contract: zero `if` / `switch` on fact CONTENT.
// Filtering for relevance (skip non-S3 assets when grouping
// S3 facts) is fine; filtering on what the facts SAY is
// aggregation, which is the solver's job in L6.
type AWSS3FactGrouper struct{}

// NewAWSS3FactGrouper returns a ready-to-use grouper. No
// configuration: the grouping rule is fixed by the AWS S3
// schema.
func NewAWSS3FactGrouper() *AWSS3FactGrouper { return &AWSS3FactGrouper{} }

// GroupResources satisfies sir.ResourceFactGrouper. For each
// S3 bucket asset across the snapshot set, calls the four
// extractors and emits one ResourceFactGroup with the four
// vector slices populated.
//
// _ time.Time is the audit-time hint required by the
// interface signature; this grouper doesn't use it because the
// vectors are time-invariant per-snapshot facts.
func (g *AWSS3FactGrouper) GroupResources(snapshots []asset.Snapshot, _ time.Time) ([]sir.ResourceFactGroup, error) {
	if len(snapshots) == 0 {
		return nil, nil
	}
	// Take the latest snapshot's view as the canonical
	// fact source. AWS bucket policy / ACL / PAB / IAM are
	// configuration state, not historical events; the
	// most-recent observation is what the solver reasons over.
	latest := snapshots[len(snapshots)-1]

	out := make([]sir.ResourceFactGroup, 0)
	for i := range latest.Assets {
		bucket := latest.Assets[i]
		if string(bucket.Type) != "aws_s3_bucket" {
			continue
		}
		// Fail loud on malformed bucket policy / ACL: a swallowed parse
		// error here erases possibly-public facts and makes the bucket
		// look private to the L6 solver. Absent/empty data stays tolerant
		// (the helpers return nil, nil); only unparseable input errors.
		bucketPolicy, err := extractBucketPolicyStatements(bucket)
		if err != nil {
			return nil, err
		}
		aclGrants, err := aclGrantFactsFromBucket(bucket)
		if err != nil {
			return nil, err
		}
		group := sir.ResourceFactGroup{
			AssetID:      string(bucket.ID),
			Vendor:       "aws",
			ServiceArea:  "s3",
			BucketPolicy: bucketPolicy,
			ACLGrants:    aclGrants,
			PAB:          extractPublicAccessBlock(bucket),
			AttachedIAM:  extractIAMStatementsForAsset(bucket, latest.Identities),
			Source: sir.SourceRef{
				Kind: "asset",
				ID:   string(bucket.ID),
			},
		}
		out = append(out, group)
	}
	return out, nil
}

// aclGrantFactsFromBucket adapts the platform-layer
// acl.ACLGrant produced by 4.0.1's ExtractACLFacts into the
// SIR-layer sir.ACLGrantFact. The two types differ only in
// that the SIR fact carries an explicit SourceRef. No content
// translation; this is a pure type adaptation.
//
// Tolerant of ABSENT data: no get-bucket-acl property, or an ACL with
// zero grants, returns (nil, nil). Fail-loud on MALFORMED data:
// ExtractACLFacts errors propagate rather than collapsing to "no
// grants" — a dropped malformed grant could hide a public/any-auth
// grantee and make the bucket look private.
func aclGrantFactsFromBucket(bucket asset.Asset) ([]sir.ACLGrantFact, error) {
	raw, ok := bucket.Properties["get-bucket-acl"]
	if !ok || raw == nil {
		return nil, nil
	}
	facts, err := acl.ExtractACLFacts(raw)
	if err != nil {
		return nil, fmt.Errorf("bucket %s: get-bucket-acl present but unparseable — refusing to drop it, could hide a public grant: %w", bucket.ID, err)
	}
	if len(facts.Grants) == 0 {
		return nil, nil
	}
	bucketID := string(bucket.ID)
	out := make([]sir.ACLGrantFact, 0, len(facts.Grants))
	for _, g := range facts.Grants {
		out = append(out, sir.ACLGrantFact{
			GranteeKind:  string(g.Kind),
			GranteeURI:   g.URI,
			GranteeID:    g.ID,
			GranteeEmail: g.Email,
			Permission:   string(g.Permission),
			IsPublic:     g.IsPublic,
			IsAnyAuth:    g.IsAnyAuth,
			Source: sir.SourceRef{
				Kind: "s3_acl_grant",
				ID:   bucketID,
				Path: []string{"Grants", strconv.Itoa(g.Index), "Permission"},
			},
		})
	}
	return out, nil
}

// Compile-time assertion.
var _ sir.ResourceFactGrouper = (*AWSS3FactGrouper)(nil)
