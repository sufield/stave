package schema

import "github.com/sufield/stave/internal/core/kernel"

// s3BucketSchema declares the property paths the aws_s3_bucket
// control suite expects every extractor to populate. Derived from
// `grep -h "field:" controls/s3/**/*.yaml | awk '{print $NF}' | sort -u`
// — every path here is referenced by at least one shipped
// control.
//
// The first cut marks the storage.access.* family as Required
// (those paths are read by the high-volume "public access" and
// "broad permission" controls; an extractor that skips them
// silently dodges the most important S3 verdicts) and leaves the
// rest as Optional. The Optional tag declares them for future
// auditing — when a Stave operator wants to confirm "is every
// expected field populated", they can flip Required=true on the
// optional set and run an audit pass.
//
// Mutating this slice is intentionally easy. Add a new path with
// `{Path: "properties.X.Y", Required: bool, Doc: "..."}`; the
// validator picks it up on the next ingest call without code
// changes elsewhere.
var s3BucketSchema = Schema{
	AssetType: kernel.AssetType("aws_s3_bucket"),
	Fields: []FieldRequirement{
		// Required: the public-access core.
		{Path: "properties.storage.access.has_wildcard_principal", Required: true,
			Doc: "drives the PublicAccess family of controls"},
		{Path: "properties.storage.access.has_external_write", Required: true,
			Doc: "foundational for CrossAccountWrite controls"},
		{Path: "properties.storage.access.allows_anonymous_list", Required: true,
			Doc: "drives the AnonymousList family"},
		{Path: "properties.storage.access.exposes_bucket_policy", Required: true,
			Doc: "drives the BucketPolicyExposure controls"},

		// Required: scope / network context that controls compare against.
		{Path: "properties.storage.access.effective_network_scope", Required: true,
			Doc: "AccountScope vs NetworkScope discrimination"},
		{Path: "properties.storage.access.has_ip_condition", Required: true,
			Doc: "filters out IP-restricted grants in PublicAccess judgement"},
		{Path: "properties.storage.access.has_vpc_condition", Required: true,
			Doc: "filters out VPC-restricted grants in PublicAccess judgement"},

		// Optional: declared so an audit-mode pass can flag them
		// later, but absence is not a hard signal yet.
		{Path: "properties.storage.access.has_self_lockout_deny", Required: false,
			Doc: "bucket-policy self-lockout: a Deny over policy-management actions gated by a network condition with no admin carve-out (CTL.S3.POLICY.LOCKOUT.001)"},
		{Path: "properties.storage.access.latent_public_list", Required: false,
			Doc: "future-state signal; not consumed by any required control yet"},
		{Path: "properties.storage.access.list_via_identity", Required: false,
			Doc: "identity-side broker for ListBucket — paired with the access map"},
		{Path: "properties.storage.access.external_account_ids", Required: false,
			Doc: "cross-account enumeration set; consumed by chains, not single controls"},
		{Path: "properties.access_point.policy_allows_external", Required: false,
			Doc: "S3 access-point overlay; populated only when an AP exists"},
		{Path: "properties.access_point.underlying_bucket_policy_allows_external", Required: false,
			Doc: "AP / bucket-policy interaction; same conditional source"},
		{Path: "properties.cdn.kind", Required: false,
			Doc: "CDN composition data; absent when no CDN fronts the bucket"},
		{Path: "properties.cdn.origins_has_dangling_s3", Required: false,
			Doc: "subdomain-takeover signal via CDN; sparse by design"},
		{Path: "properties.delegation.customer_can_revoke", Required: false,
			Doc: "delegation governance; chain-side input"},
		{Path: "properties.delegation.has_expired_review", Required: false,
			Doc: "delegation governance; chain-side input"},
		{Path: "properties.delegation.has_scope_exceeded", Required: false,
			Doc: "delegation governance; chain-side input"},
		{Path: "properties.delegation.has_unknown_external_principal", Required: false,
			Doc: "delegation governance; chain-side input"},
		{Path: "properties.delegation.vendor_can_make_public", Required: false,
			Doc: "delegation governance; chain-side input"},
		{Path: "properties.s3_ref.bucket_exists", Required: false,
			Doc: "dangling-reference signal; only meaningful when the asset is a reference, not the bucket"},
		{Path: "properties.s3_ref.bucket_owned", Required: false,
			Doc: "cross-account ownership signal; same conditional source"},
	},
}

func init() {
	Register(s3BucketSchema)
}
