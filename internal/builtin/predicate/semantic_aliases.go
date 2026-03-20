// semantic_aliases.go provides named shorthand predicates for common S3
// security conditions. Instead of writing verbose field-level predicate
// rules in every control, authors reference a semantic alias like
// "s3.is_public_readable" and the engine expands it into the full
// UnsafePredicate (e.g. checking public_read, read_via_identity,
// and read_via_resource).
//
// The registry is immutable at runtime: init() validates every entry and
// Resolve returns a deep copy so callers cannot mutate the backing data.
package predicate

import (
	"fmt"
	"slices"

	"github.com/sufield/stave/pkg/alpha/domain/policy"
	"github.com/sufield/stave/pkg/alpha/domain/predicate"
)

// ── Phase 1.1: Alias Name Constants ──────────────────────────────────

const (
	S3IsPublicReadable               = "s3.is_public_readable"
	S3IsPublicWritable               = "s3.is_public_writable"
	S3IsPublicListable               = "s3.is_public_listable"
	S3LatentPublicRead               = "s3.latent_public_read"
	S3LatentPublicList               = "s3.latent_public_list"
	S3AuthenticatedUsersRead         = "s3.authenticated_users_read"
	S3AuthenticatedUsersWrite        = "s3.authenticated_users_write"
	S3ACLWritable                    = "s3.acl_writable"
	S3ACLReadableByPublic            = "s3.acl_readable_by_public"
	S3HasFullControlGrant            = "s3.has_full_control_grant"
	S3EncryptionAtRestDisabled       = "s3.encryption_at_rest_disabled"
	S3EncryptionInTransitNotEnforced = "s3.encryption_in_transit_not_enforced"
	S3NotUsingKMSCMK                 = "s3.not_using_kms_cmk"
	S3LoggingDisabled                = "s3.logging_disabled"
	S3VersioningDisabled             = "s3.versioning_disabled"
	S3MFADeleteDisabled              = "s3.mfa_delete_disabled"
	S3PublicAccessBlockDisabled      = "s3.public_access_block_disabled"
	S3ObjectLockDisabled             = "s3.object_lock_disabled"
	S3ObjectLockNotComplianceMode    = "s3.object_lock_not_compliance_mode"
)

// ── Phase 2.1: Categories ────────────────────────────────────────────

const (
	CategoryPublicExposure      = "Public Exposure"
	CategoryLatentExposure      = "Latent Exposure"
	CategoryAuthenticatedAccess = "Authenticated Access"
	CategoryAdminGrants         = "Admin Grants"
	CategoryEncryption          = "Encryption"
	CategoryLogging             = "Logging"
	CategoryVersioning          = "Versioning"
	CategoryControls            = "Controls"
	CategoryObjectLock          = "Object Lock"
)

// ── Phase 2.1: Alias Entry ──────────────────────────────────────────

// aliasEntry bundles a predicate with human-readable metadata.
type aliasEntry struct {
	Predicate   policy.UnsafePredicate
	Description string
	Category    string
	Service     string // Phase 4.1: service grouping key
}

// ── Phase 2.3: Error Type ────────────────────────────────────────────

// UnknownAliasError is returned when an alias cannot be resolved.
// If a close match exists, Suggestion is populated.
type UnknownAliasError struct {
	Name       string
	Suggestion string
}

func (e *UnknownAliasError) Error() string {
	if e.Suggestion != "" {
		return fmt.Sprintf("unknown alias %q; did you mean %q?", e.Name, e.Suggestion)
	}
	return fmt.Sprintf("unknown alias %q", e.Name)
}

// ── Phase 4.2: Resolver Interface ────────────────────────────────────

// Resolver resolves alias names to expanded predicates. Adopters can
// implement this interface to provide custom aliases alongside the
// built-in S3 set.
type Resolver interface {
	// Resolve returns a deep copy of the expanded predicate for an alias.
	// Returns an *UnknownAliasError if the alias is not found.
	Resolve(name string) (policy.UnsafePredicate, error)

	// ListAliases returns alias names in sorted order. Pass "" for all
	// aliases, or a category name to filter.
	ListAliases(category string) []string
}

// ── Phase 4.1: Multi-Service Registry ────────────────────────────────

// Registry is a multi-service alias registry. Aliases are grouped by
// service internally but maintain a flat naming convention (e.g.
// "s3.is_public_readable") for the public API.
type Registry struct {
	entries map[string]aliasEntry
}

// compile-time interface check.
var _ Resolver = (*Registry)(nil)

// Resolve returns a deep copy of the expanded predicate for an alias.
func (r *Registry) Resolve(name string) (policy.UnsafePredicate, error) {
	entry, ok := r.entries[name]
	if !ok {
		return policy.UnsafePredicate{}, r.suggestError(name)
	}
	return clonePredicate(entry.Predicate), nil
}

// ListAliases returns alias names in sorted order. Pass "" for all
// aliases, or a category name to filter.
func (r *Registry) ListAliases(category string) []string {
	out := make([]string, 0, len(r.entries))
	for name, entry := range r.entries {
		if category == "" || entry.Category == category {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// AliasInfo provides metadata about a registered alias.
type AliasInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"`
	Service     string `json:"service"`
}

// ListAliasInfo returns full metadata for all aliases matching the
// category filter. Pass "" for all.
func (r *Registry) ListAliasInfo(category string) []AliasInfo {
	out := make([]AliasInfo, 0, len(r.entries))
	for name, entry := range r.entries {
		if category == "" || entry.Category == category {
			out = append(out, AliasInfo{
				Name:        name,
				Description: entry.Description,
				Category:    entry.Category,
				Service:     entry.Service,
			})
		}
	}
	slices.SortFunc(out, func(a, b AliasInfo) int {
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}
		return 0
	})
	return out
}

// AliasResolverFunc returns a policy.AliasResolver backed by this
// registry, suitable for WithAliasResolver in the control loader.
func (r *Registry) AliasResolverFunc() policy.AliasResolver {
	return func(name string) (policy.UnsafePredicate, bool) {
		pred, err := r.Resolve(name)
		return pred, err == nil
	}
}

// ── Phase 4.2: Composite Resolver ────────────────────────────────────

// CompositeResolver chains multiple resolvers, trying each in order.
// This lets adopters layer custom aliases on top of the built-in set.
type CompositeResolver struct {
	resolvers []Resolver
}

// NewCompositeResolver creates a resolver that tries each delegate in order.
func NewCompositeResolver(resolvers ...Resolver) *CompositeResolver {
	return &CompositeResolver{resolvers: resolvers}
}

// Resolve tries each delegate in order and returns the first match.
func (c *CompositeResolver) Resolve(name string) (policy.UnsafePredicate, error) {
	for _, r := range c.resolvers {
		pred, err := r.Resolve(name)
		if err == nil {
			return pred, nil
		}
	}
	return policy.UnsafePredicate{}, &UnknownAliasError{Name: name}
}

// ListAliases merges and deduplicates aliases from all delegates.
func (c *CompositeResolver) ListAliases(category string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, r := range c.resolvers {
		for _, name := range r.ListAliases(category) {
			if _, ok := seen[name]; !ok {
				seen[name] = struct{}{}
				out = append(out, name)
			}
		}
	}
	slices.Sort(out)
	return out
}

// ── Default (built-in) registry ──────────────────────────────────────

var defaultRegistry = newBuiltinRegistry()

// DefaultRegistry returns the built-in registry instance.
func DefaultRegistry() *Registry { return defaultRegistry }

// Resolve looks up an alias by name in the default built-in registry.
func Resolve(name string) (policy.UnsafePredicate, error) {
	return defaultRegistry.Resolve(name)
}

// ListAliases returns alias names from the default registry. Pass ""
// for all aliases, or a category name to filter.
func ListAliases(category string) []string {
	return defaultRegistry.ListAliases(category)
}

// ResolverFunc returns a policy.AliasResolver backed by the default
// built-in registry.
func ResolverFunc() policy.AliasResolver {
	return defaultRegistry.AliasResolverFunc()
}

// ── Phase 1.3: Init-time integrity check ─────────────────────────────

func init() {
	for name, entry := range defaultRegistry.entries {
		validateEntry(name, entry)
	}
}

func validateEntry(name string, entry aliasEntry) {
	for i, rule := range entry.Predicate.Any {
		validateRule(name, "any", i, rule)
	}
	for i, rule := range entry.Predicate.All {
		validateRule(name, "all", i, rule)
	}
}

func validateRule(alias, block string, idx int, rule policy.PredicateRule) {
	if !rule.Field.IsZero() {
		if rule.Field.String() == "" {
			panic(fmt.Sprintf("alias %q: %s[%d] has empty FieldPath", alias, block, idx))
		}
		if !predicate.IsSupported(rule.Op) {
			panic(fmt.Sprintf("alias %q: %s[%d] has unsupported operator %q", alias, block, idx, rule.Op))
		}
	}
	for i, sub := range rule.Any {
		validateRule(alias, fmt.Sprintf("%s[%d].any", block, idx), i, sub)
	}
	for i, sub := range rule.All {
		validateRule(alias, fmt.Sprintf("%s[%d].all", block, idx), i, sub)
	}
}

// ── Phase 1.2: Deep clone ────────────────────────────────────────────

func clonePredicate(in policy.UnsafePredicate) policy.UnsafePredicate {
	return policy.UnsafePredicate{
		Any: cloneRules(in.Any),
		All: cloneRules(in.All),
	}
}

func cloneRules(rules []policy.PredicateRule) []policy.PredicateRule {
	if len(rules) == 0 {
		return nil
	}
	out := make([]policy.PredicateRule, len(rules))
	for i, r := range rules {
		out[i] = cloneRule(r)
	}
	return out
}

func cloneRule(r policy.PredicateRule) policy.PredicateRule {
	return policy.PredicateRule{
		Field:          r.Field,
		Op:             r.Op,
		Value:          r.Value,
		ValueFromParam: r.ValueFromParam,
		Any:            cloneRules(r.Any),
		All:            cloneRules(r.All),
	}
}

// ── Phase 2.3: Fuzzy suggestion ──────────────────────────────────────

func (r *Registry) suggestError(name string) *UnknownAliasError {
	best := ""
	bestDist := -1
	for candidate := range r.entries {
		d := levenshtein(name, candidate)
		if bestDist < 0 || d < bestDist {
			bestDist = d
			best = candidate
		}
	}
	// Only suggest if edit distance is reasonable (≤40% of the longer string).
	suggestion := ""
	if bestDist >= 0 {
		maxLen := max(len(name), len(best))
		if maxLen > 0 && bestDist <= maxLen*2/5 {
			suggestion = best
		}
	}
	return &UnknownAliasError{Name: name, Suggestion: suggestion}
}

func levenshtein(a, b string) int {
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}
	prev := make([]int, len(b)+1)
	curr := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min(curr[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[len(b)]
}

// ── Built-in alias definitions ───────────────────────────────────────

func newBuiltinRegistry() *Registry {
	return &Registry{entries: builtinAliases()}
}

func builtinAliases() map[string]aliasEntry {
	return map[string]aliasEntry{
		// ── Public exposure (composite) ──────────────────────────
		S3IsPublicReadable: {
			Description: "Any path grants public read access (direct, identity-based, or resource-based)",
			Category:    CategoryPublicExposure,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.access.public_read"), Op: predicate.OpEq, Value: policy.Bool(true)},
					{Field: predicate.NewFieldPath("properties.storage.access.read_via_identity"), Op: predicate.OpEq, Value: policy.Bool(true)},
					{Field: predicate.NewFieldPath("properties.storage.access.read_via_resource"), Op: predicate.OpEq, Value: policy.Bool(true)},
				},
			},
		},
		S3IsPublicWritable: {
			Description: "Any path grants public write access (direct or resource-based)",
			Category:    CategoryPublicExposure,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.access.public_write"), Op: predicate.OpEq, Value: policy.Bool(true)},
					{Field: predicate.NewFieldPath("properties.storage.access.write_via_resource"), Op: predicate.OpEq, Value: policy.Bool(true)},
				},
			},
		},
		S3IsPublicListable: {
			Description: "Any path grants public list access (direct or identity-based)",
			Category:    CategoryPublicExposure,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.access.public_list"), Op: predicate.OpEq, Value: policy.Bool(true)},
					{Field: predicate.NewFieldPath("properties.storage.access.list_via_identity"), Op: predicate.OpEq, Value: policy.Bool(true)},
				},
			},
		},

		// ── Latent exposure (masked by public access block only) ─
		S3LatentPublicRead: {
			Description: "Latent public read access masked only by public access block",
			Category:    CategoryLatentExposure,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.access.latent_public_read"), Op: predicate.OpEq, Value: policy.Bool(true)},
				},
			},
		},
		S3LatentPublicList: {
			Description: "Latent public list access masked only by public access block",
			Category:    CategoryLatentExposure,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.access.latent_public_list"), Op: predicate.OpEq, Value: policy.Bool(true)},
				},
			},
		},

		// ── Authenticated-users access ───────────────────────────
		S3AuthenticatedUsersRead: {
			Description: "Read access granted to all authenticated AWS users",
			Category:    CategoryAuthenticatedAccess,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.access.authenticated_read"), Op: predicate.OpEq, Value: policy.Bool(true)},
				},
			},
		},
		S3AuthenticatedUsersWrite: {
			Description: "Write access granted to all authenticated AWS users",
			Category:    CategoryAuthenticatedAccess,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.access.authenticated_write"), Op: predicate.OpEq, Value: policy.Bool(true)},
				},
			},
		},

		// ── Admin grants ─────────────────────────────────────────
		S3ACLWritable: {
			Description: "ACL grants write-ACP to public or all authenticated users",
			Category:    CategoryAdminGrants,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.access.public_admin"), Op: predicate.OpEq, Value: policy.Bool(true)},
					{Field: predicate.NewFieldPath("properties.storage.access.authenticated_admin"), Op: predicate.OpEq, Value: policy.Bool(true)},
				},
			},
		},
		S3ACLReadableByPublic: {
			Description: "ACL read-ACP granted to the public",
			Category:    CategoryAdminGrants,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.access.public_admin"), Op: predicate.OpEq, Value: policy.Bool(true)},
				},
			},
		},
		S3HasFullControlGrant: {
			Description: "FULL_CONTROL grant to public or all authenticated users",
			Category:    CategoryAdminGrants,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.access.has_full_control_public"), Op: predicate.OpEq, Value: policy.Bool(true)},
					{Field: predicate.NewFieldPath("properties.storage.access.has_full_control_authenticated"), Op: predicate.OpEq, Value: policy.Bool(true)},
				},
			},
		},

		// ── Encryption ───────────────────────────────────────────
		S3EncryptionAtRestDisabled: {
			Description: "Server-side encryption at rest is not enabled",
			Category:    CategoryEncryption,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.encryption.at_rest_enabled"), Op: predicate.OpEq, Value: policy.Bool(false)},
				},
			},
		},
		S3EncryptionInTransitNotEnforced: {
			Description: "Bucket policy does not enforce TLS for data in transit",
			Category:    CategoryEncryption,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.encryption.in_transit_enforced"), Op: predicate.OpEq, Value: policy.Bool(false)},
				},
			},
		},
		S3NotUsingKMSCMK: {
			Description: "Encryption does not use a customer-managed KMS key",
			Category:    CategoryEncryption,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.encryption.algorithm"), Op: predicate.OpNe, Value: policy.Str("aws:kms")},
					{Field: predicate.NewFieldPath("properties.storage.encryption.kms_key_id"), Op: predicate.OpEq, Value: policy.Str("")},
				},
			},
		},

		// ── Logging ──────────────────────────────────────────────
		S3LoggingDisabled: {
			Description: "Server access logging is not enabled",
			Category:    CategoryLogging,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.logging.enabled"), Op: predicate.OpEq, Value: policy.Bool(false)},
				},
			},
		},

		// ── Versioning ───────────────────────────────────────────
		S3VersioningDisabled: {
			Description: "Bucket versioning is not enabled",
			Category:    CategoryVersioning,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.versioning.enabled"), Op: predicate.OpEq, Value: policy.Bool(false)},
				},
			},
		},
		S3MFADeleteDisabled: {
			Description: "MFA delete protection is not enabled",
			Category:    CategoryVersioning,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.versioning.mfa_delete_enabled"), Op: predicate.OpEq, Value: policy.Bool(false)},
				},
			},
		},

		// ── Controls ─────────────────────────────────────────────
		S3PublicAccessBlockDisabled: {
			Description: "S3 public access block is not fully enabled",
			Category:    CategoryControls,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.controls.public_access_fully_blocked"), Op: predicate.OpEq, Value: policy.Bool(false)},
				},
			},
		},

		// ── Object lock ──────────────────────────────────────────
		S3ObjectLockDisabled: {
			Description: "Object Lock is not enabled on the bucket",
			Category:    CategoryObjectLock,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.object_lock.enabled"), Op: predicate.OpEq, Value: policy.Bool(false)},
				},
			},
		},
		S3ObjectLockNotComplianceMode: {
			Description: "Object Lock is enabled but not in COMPLIANCE mode",
			Category:    CategoryObjectLock,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				All: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.object_lock.enabled"), Op: predicate.OpEq, Value: policy.Bool(true)},
					{Field: predicate.NewFieldPath("properties.storage.object_lock.mode"), Op: predicate.OpNe, Value: policy.Str("COMPLIANCE")},
				},
			},
		},
	}
}
