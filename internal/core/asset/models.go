package asset

import (
	"maps"

	"github.com/sufield/stave/internal/core/kernel"
)

// SourceRef points to the source file and line where the asset is defined.
type SourceRef struct {
	File string `json:"file"`
	Line int    `json:"line"`
}

// Asset represents a single infrastructure component such as an S3 bucket,
// IAM role, or database instance. Properties contain vendor-specific attributes
// that predicates evaluate to determine if the asset is unsafe.
type Asset struct {
	ID         ID               `json:"id"`
	Type       kernel.AssetType `json:"type"`
	Vendor     kernel.Vendor    `json:"vendor"`
	Properties map[string]any   `json:"properties"`
	Source     *SourceRef       `json:"source,omitempty"`
}

// Map returns predicate-evaluable properties including core fields.
// Mirrors CloudIdentity.Map() so the predicate engine sees a consistent
// set of base fields (id, type, vendor) across all evaluated components.
func (r Asset) Map() map[string]any {
	out := make(map[string]any, len(r.Properties)+3)
	out["id"] = r.ID
	out["type"] = r.Type
	out["vendor"] = r.Vendor
	if r.Properties != nil {
		maps.Copy(out, r.Properties)
	}
	return out
}

// IsProvablySafe reports whether the asset's safety_provable property is
// explicitly true. Returns false when the property is missing or false.
func (r Asset) IsProvablySafe() bool {
	provable, ok := r.Properties["safety_provable"].(bool)
	return ok && provable
}

// IsType reports whether the asset's type matches the given string.
// Replaces (string(a.Type) != in.AssetType) probes — see
// internal/app/celeval/eval.go:51 — with a typed comparison that
// keeps the kernel.AssetType-string boundary inside the asset
// package.
func (r Asset) IsType(t string) bool {
	return string(r.Type) == t
}

// identityAssetTypes lists asset types that represent IAM identities
// for ranking and reporting purposes. Centralised here (rather than
// in internal/app/rank where it used to live) so producers and
// consumers cannot drift on the type set; consumers ask the asset
// directly via IsIdentityAsset.
//
// Wire values match the kernel.AssetType strings emitted by the
// snapshot extractors. The mapped string is the short identity
// classification surfaced in identity-rank reports — kept in this
// table so adding a new identity type is one edit.
var identityAssetTypes = map[kernel.AssetType]string{
	"aws_iam_role":       "role",
	"aws_iam_user":       "user",
	"aws_iam_access_key": "access_key",
}

// IsIdentityAsset reports whether the asset's Type identifies an
// IAM principal (role, user, access key). Replaces the external
// (identityAssetTypes[a.Type]) map probe at
// internal/app/rank/identity.go:121 so consumers stop reaching for
// a package-level lookup table to ask a question about the asset.
func (r Asset) IsIdentityAsset() bool {
	_, ok := identityAssetTypes[r.Type]
	return ok
}

// IdentityClassification returns the short identity-type label
// ("role", "user", "access_key") for an identity asset, or "" for
// non-identity assets. Pairs with IsIdentityAsset so rank/identity
// can drop the per-call map dereference.
func (r Asset) IdentityClassification() string {
	return identityAssetTypes[r.Type]
}

// IsIdentityAssetType reports whether the supplied asset type maps
// to an IAM principal. Useful for callers that have an
// kernel.AssetType in hand without an enclosing Asset (e.g.
// Finding.AssetType in rank/identity.go).
func IsIdentityAssetType(t kernel.AssetType) bool {
	_, ok := identityAssetTypes[t]
	return ok
}

// IdentityClassificationFor returns the short identity-type label
// for a kernel.AssetType, or "" when the type is not an identity.
// Companion to IdentityClassification for callers without an
// enclosing Asset value.
func IdentityClassificationFor(t kernel.AssetType) string {
	return identityAssetTypes[t]
}

// CloudIdentity represents an IAM identity such as a user, role, or service account.
// Identity attributes are stored in a flexible properties map so predicate evaluation
// can use a unified model across both assets and identities.
type CloudIdentity struct {
	ID         ID               `json:"id"`
	Type       kernel.AssetType `json:"type"` // e.g., "iam_role", "service_account"
	Vendor     kernel.Vendor    `json:"vendor"`
	Properties map[string]any   `json:"properties"`
	Source     *SourceRef       `json:"source,omitempty"`
}

// Map returns predicate-evaluable identity attributes as a flat map.
// Identity core fields are included so predicates can match on "type", "vendor", and "id"
// without reaching into struct fields. Domain types are stored directly to avoid
// per-call String() allocations; the predicate engine handles typed-string comparison.
func (id CloudIdentity) Map() map[string]any {
	out := make(map[string]any, len(id.Properties)+3)
	out["id"] = id.ID
	out["type"] = id.Type
	out["vendor"] = id.Vendor
	if id.Properties != nil {
		maps.Copy(out, id.Properties)
	}
	return out
}

// ExemptedAsset represents an asset that was skipped due to exemption rules.
type ExemptedAsset struct {
	ID      ID     `json:"asset_id"`
	Pattern string `json:"matched_pattern"`
	Reason  string `json:"reason"`
}
