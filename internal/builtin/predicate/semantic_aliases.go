// semantic_aliases.go provides named shorthand predicates for common S3
// security conditions. Instead of writing verbose field-level predicate
// rules in every control, authors reference a semantic alias like
// "s3.is_public_readable" and the engine expands it into the full
// UnsafePredicate (e.g. checking public_read, read_via_identity,
// and read_via_resource).
//
// Categories: public exposure, latent exposure, authenticated-users
// access, admin grants, encryption, logging, versioning, controls, and
// object lock.
//
// Resolve returns a deep copy so callers cannot mutate the registry.
package predicate

import (
	"slices"

	"github.com/sufield/stave/internal/domain/policy"
)

var aliasMap = map[string]policy.UnsafePredicate{
	// ── Public exposure (composite) ───────────────────────────────
	"s3.is_public_readable": {
		Any: []policy.PredicateRule{
			{Field: "properties.storage.visibility.public_read", Op: "eq", Value: true},
			{Field: "properties.storage.visibility.read_via_identity", Op: "eq", Value: true},
			{Field: "properties.storage.visibility.read_via_resource", Op: "eq", Value: true},
		},
	},
	"s3.is_public_writable": {
		Any: []policy.PredicateRule{
			{Field: "properties.storage.visibility.public_write", Op: "eq", Value: true},
			{Field: "properties.storage.visibility.write_via_resource", Op: "eq", Value: true},
		},
	},
	"s3.is_public_listable": {
		Any: []policy.PredicateRule{
			{Field: "properties.storage.visibility.public_list", Op: "eq", Value: true},
			{Field: "properties.storage.visibility.list_via_identity", Op: "eq", Value: true},
		},
	},

	// ── Latent exposure (masked by public access block only) ──────
	"s3.latent_public_read": {
		Any: []policy.PredicateRule{
			{Field: "properties.storage.visibility.latent_public_read", Op: "eq", Value: true},
		},
	},
	"s3.latent_public_list": {
		Any: []policy.PredicateRule{
			{Field: "properties.storage.visibility.latent_public_list", Op: "eq", Value: true},
		},
	},

	// ── Authenticated-users access ────────────────────────────────
	"s3.authenticated_users_read": {
		Any: []policy.PredicateRule{
			{Field: "properties.storage.visibility.authenticated_read", Op: "eq", Value: true},
		},
	},
	"s3.authenticated_users_write": {
		Any: []policy.PredicateRule{
			{Field: "properties.storage.visibility.authenticated_write", Op: "eq", Value: true},
		},
	},

	// ── Admin grants ─────────────────────────────────────────────
	"s3.acl_writable": {
		Any: []policy.PredicateRule{
			{Field: "properties.storage.visibility.public_admin", Op: "eq", Value: true},
			{Field: "properties.storage.visibility.authenticated_admin", Op: "eq", Value: true},
		},
	},
	"s3.acl_readable_by_public": {
		Any: []policy.PredicateRule{
			{Field: "properties.storage.visibility.public_admin", Op: "eq", Value: true},
		},
	},
	"s3.has_full_control_grant": {
		Any: []policy.PredicateRule{
			{Field: "properties.storage.acl.has_full_control_public", Op: "eq", Value: true},
			{Field: "properties.storage.acl.has_full_control_authenticated", Op: "eq", Value: true},
		},
	},

	// ── Encryption ────────────────────────────────────────────────
	"s3.encryption_at_rest_disabled": {
		Any: []policy.PredicateRule{
			{Field: "properties.storage.encryption.at_rest_enabled", Op: "eq", Value: false},
		},
	},
	"s3.encryption_in_transit_not_enforced": {
		Any: []policy.PredicateRule{
			{Field: "properties.storage.encryption.in_transit_enforced", Op: "eq", Value: false},
		},
	},
	"s3.not_using_kms_cmk": {
		Any: []policy.PredicateRule{
			{Field: "properties.storage.encryption.algorithm", Op: "ne", Value: "aws:kms"},
			{Field: "properties.storage.encryption.kms_key_id", Op: "eq", Value: ""},
		},
	},

	// ── Logging ───────────────────────────────────────────────────
	"s3.logging_disabled": {
		Any: []policy.PredicateRule{
			{Field: "properties.storage.logging.enabled", Op: "eq", Value: false},
		},
	},

	// ── Versioning ────────────────────────────────────────────────
	"s3.versioning_disabled": {
		Any: []policy.PredicateRule{
			{Field: "properties.storage.versioning.enabled", Op: "eq", Value: false},
		},
	},
	"s3.mfa_delete_disabled": {
		Any: []policy.PredicateRule{
			{Field: "properties.storage.versioning.mfa_delete_enabled", Op: "eq", Value: false},
		},
	},

	// ── Controls ──────────────────────────────────────────────────
	"s3.public_access_block_disabled": {
		Any: []policy.PredicateRule{
			{Field: "properties.storage.controls.public_access_fully_blocked", Op: "eq", Value: false},
		},
	},

	// ── Object lock ───────────────────────────────────────────────
	"s3.object_lock_disabled": {
		Any: []policy.PredicateRule{
			{Field: "properties.storage.object_lock.enabled", Op: "eq", Value: false},
		},
	},
	"s3.object_lock_not_compliance_mode": {
		All: []policy.PredicateRule{
			{Field: "properties.storage.object_lock.enabled", Op: "eq", Value: true},
			{Field: "properties.storage.object_lock.mode", Op: "ne", Value: "COMPLIANCE"},
		},
	},
}

// ListAliases returns built-in semantic predicate aliases in stable order.
func ListAliases() []string {
	out := make([]string, 0, len(aliasMap))
	for name := range aliasMap {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

// Resolve returns the expanded predicate for an alias.
func Resolve(name string) (policy.UnsafePredicate, bool) {
	pred, ok := aliasMap[name]
	if !ok {
		return policy.UnsafePredicate{}, false
	}
	return clonePredicate(pred), true
}

func clonePredicate(in policy.UnsafePredicate) policy.UnsafePredicate {
	out := policy.UnsafePredicate{}
	if len(in.Any) > 0 {
		out.Any = slices.Clone(in.Any)
	}
	if len(in.All) > 0 {
		out.All = slices.Clone(in.All)
	}
	return out
}
