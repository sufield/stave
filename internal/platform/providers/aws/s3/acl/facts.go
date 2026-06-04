package acl

import (
	"fmt"
	"strings"
)

// GranteeKind classifies an ACL grant's grantee type. The set
// matches AWS's `Type` field on the Grantee element of
// get-bucket-acl: CanonicalUser, Group, AmazonCustomerByEmail.
// Stored as a typed string rather than an enum so the wire
// representation in SIR JSON / debug output is self-explanatory.
type GranteeKind string

// Grantee kinds.
const (
	GranteeCanonicalUser GranteeKind = "CanonicalUser"
	GranteeGroup         GranteeKind = "Group"
	GranteeEmail         GranteeKind = "AmazonCustomerByEmail"
)

// ACLPermission is an S3 ACL permission as it appears on the
// wire. Distinct from the existing Permission alias in grant.go
// (which models permissions as strings without enum constants);
// the two coexist because grant.go's Permission flows into the
// risk.Permission bitmask used by the legacy assessor, while
// ACLPermission is the SIR-facing typed view that downstream
// translators (sirbridge → SIR Action lists) consume.
type ACLPermission string

// ACL permissions.
const (
	ACLPermissionRead        ACLPermission = "READ"
	ACLPermissionWrite       ACLPermission = "WRITE"
	ACLPermissionReadACP     ACLPermission = "READ_ACP"
	ACLPermissionWriteACP    ACLPermission = "WRITE_ACP"
	ACLPermissionFullControl ACLPermission = "FULL_CONTROL"
)

// ACLGrant is the typed, SIR-bound view of one ACL grant.
//
// Index records the grant's position in the original
// `Grants` array on the snapshot. The SIR aggregator uses Index
// to build a SourceRef path of the form
// ["Grants", strconv.Itoa(g.Index), "Permission"], which
// downstream consumers (the explainer, the future Z3 fix
// suggester) follow to navigate to the exact line in the
// original AWS get-bucket-acl JSON.
//
// IsPublic is true when the grantee is the AllUsers group
// URI; IsAnyAuth is true when it's the AuthenticatedUsers
// group URI. The two are mutually exclusive but both can be
// false (group grants for s3-internal services like
// LogDelivery, or canonical-user grants).
type ACLGrant struct {
	Index      int
	Kind       GranteeKind
	URI        string
	ID         string
	Email      string
	Permission ACLPermission
	IsPublic   bool
	IsAnyAuth  bool
}

// ACLFacts is the typed view of a bucket's complete ACL state.
// OwnerID is the canonical-user ID of the bucket owner from
// the AWS get-bucket-acl Owner element; Grants is the
// chronologically-ordered list of grants. An empty Grants
// slice is valid (an ACL exists but grants nobody anything
// beyond the owner).
type ACLFacts struct {
	OwnerID string
	Grants  []ACLGrant
}

// AWS canonical group URIs. The full URIs are pinned here so
// extractors and the SIR aggregator agree on the exact strings
// to match against — a typo in one but not the other would
// silently misclassify public grants.
const (
	GroupURIAllUsers           = "http://acs.amazonaws.com/groups/global/AllUsers"
	GroupURIAuthenticatedUsers = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
	GroupURILogDelivery        = "http://acs.amazonaws.com/groups/s3/LogDelivery"
)

// ExtractACLFacts parses the value at
// asset.Properties["get-bucket-acl"] (which AWS CLI decode
// produces as map[string]any) into typed ACLFacts.
//
// Tolerant of ABSENT data: a nil rawProperty or an absent Grants array yields
// ACLFacts{Grants: nil} with no error ("no ACL data" is a valid state).
//
// Fail-loud on MALFORMED data: a grant whose element is not an object, or whose
// Grantee/Permission cannot be type-asserted, returns an error rather than being
// silently dropped — a dropped malformed grant could hide a public/any-auth
// grant and make the bucket look private. Returns an error when the top-level
// shape is wrong (rawProperty is a non-nil non-map) or any grant is unparseable.
func ExtractACLFacts(rawProperty any) (ACLFacts, error) {
	if rawProperty == nil {
		return ACLFacts{}, nil
	}
	root, isMap := rawProperty.(map[string]any)
	if !isMap {
		return ACLFacts{}, fmt.Errorf("acl: expected map, got %T", rawProperty)
	}

	out := ACLFacts{}

	if owner, hasOwner := root["Owner"].(map[string]any); hasOwner {
		if id, hasID := owner["ID"].(string); hasID {
			out.OwnerID = id
		}
	}

	rawGrants, hasGrants := root["Grants"].([]any)
	if !hasGrants {
		// Grants absent or not an array — return a valid empty
		// ACL. AWS occasionally returns an ACL with no Grants
		// key at all when the bucket policy fully replaces ACL
		// semantics (BucketOwnerEnforced).
		return out, nil
	}

	for i, raw := range rawGrants {
		grant, ok := raw.(map[string]any)
		if !ok {
			// Fail-loud: a grant we can't parse must NOT be silently dropped —
			// a malformed public/any-authenticated grant would vanish from the
			// ACL and the bucket would look private. Error so the ACL is treated
			// as unparseable, not as "fewer grants".
			return ACLFacts{}, fmt.Errorf("acl: grant %d is not an object (%T); refusing to drop it — could hide a public grant", i, raw)
		}
		parsed, ok := parseGrant(i, grant)
		if !ok {
			return ACLFacts{}, fmt.Errorf("acl: grant %d has an unparseable Grantee/Permission; refusing to drop it — could hide a public grant", i)
		}
		out.Grants = append(out.Grants, parsed)
	}
	return out, nil
}

// parseGrant translates one element of the Grants array into a
// typed ACLGrant. Returns ok=false when the grantee or
// permission cannot be type-asserted; the caller turns that into
// a parse error (a malformed grant is never silently dropped).
func parseGrant(index int, raw map[string]any) (ACLGrant, bool) {
	granteeRaw, ok := raw["Grantee"].(map[string]any)
	if !ok {
		return ACLGrant{}, false
	}
	permRaw, ok := raw["Permission"].(string)
	if !ok {
		return ACLGrant{}, false
	}

	g := ACLGrant{
		Index:      index,
		Permission: ACLPermission(strings.ToUpper(strings.TrimSpace(permRaw))),
	}

	if kind, ok := granteeRaw["Type"].(string); ok {
		g.Kind = GranteeKind(strings.TrimSpace(kind))
	}
	if uri, ok := granteeRaw["URI"].(string); ok {
		g.URI = strings.TrimSpace(uri)
	}
	if id, ok := granteeRaw["ID"].(string); ok {
		g.ID = strings.TrimSpace(id)
	}
	if email, ok := granteeRaw["EmailAddress"].(string); ok {
		g.Email = strings.TrimSpace(email)
	}

	// Public / authenticated flags derive from the URI for
	// group grantees. AWS uses fixed canonical URIs; matching
	// against the constants above keeps extractors and the SIR
	// aggregator in agreement on the exact substring.
	switch g.URI {
	case GroupURIAllUsers:
		g.IsPublic = true
	case GroupURIAuthenticatedUsers:
		g.IsAnyAuth = true
	}
	return g, true
}
