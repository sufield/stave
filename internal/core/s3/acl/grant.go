package acl

import (
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/core/evaluation/risk"
)

// ACLPermission represents an S3 ACL permission string.
type ACLPermission string

const (
	ACLPermRead        ACLPermission = "READ"
	ACLPermWrite       ACLPermission = "WRITE"
	ACLPermReadACP     ACLPermission = "READ_ACP"
	ACLPermWriteACP    ACLPermission = "WRITE_ACP"
	ACLPermFullControl ACLPermission = "FULL_CONTROL"
)

// Audience classifies the reach of an ACL grant.
type Audience int

const (
	// AudiencePrivate targets specific accounts or canonical users.
	AudiencePrivate Audience = iota
	// AudienceAllUsers targets the public internet (AllUsers group).
	AudienceAllUsers
	// AudienceAuthenticatedOnly targets any authenticated AWS user.
	AudienceAuthenticatedOnly
)

// String returns the canonical text label for the audience.
func (a Audience) String() string {
	switch a {
	case AudienceAllUsers:
		return "all_users"
	case AudienceAuthenticatedOnly:
		return "authenticated"
	default:
		return "private"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (a Audience) MarshalText() ([]byte, error) {
	return []byte(a.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (a *Audience) UnmarshalText(text []byte) error {
	switch strings.ToLower(string(text)) {
	case "all_users", "public":
		*a = AudienceAllUsers
	case "authenticated", "auth":
		*a = AudienceAuthenticatedOnly
	case "private":
		*a = AudiencePrivate
	default:
		return fmt.Errorf("acl: invalid audience %q", text)
	}
	return nil
}

// Grant represents a single entry in an S3 Access Control List.
type Grant struct {
	Grantee    string        `json:"grantee"`    // Group URI or canonical ID
	Permission ACLPermission `json:"permission"` // READ, WRITE, etc.
}

// Grants is a collection helper for ACL grant slices.
type Grants []Grant

// Audience determines who the grant applies to by inspecting the Grantee URI.
// Delegates to classifyGrantee for the actual suffix matching.
func (g Grant) Audience() Audience {
	return classifyGrantee(g.Grantee)
}

// IsPublic reports whether this grant applies to public or authenticated principals.
func (g Grant) IsPublic() bool {
	return g.Audience() != AudiencePrivate
}

// HasFullControl reports whether the grant includes FULL_CONTROL.
func (g Grant) HasFullControl() bool {
	return strings.EqualFold(string(g.Permission), string(ACLPermFullControl))
}

// Permissions maps the S3 ACL permission to the domain risk bitmask.
func (g Grant) Permissions() risk.Permission {
	p := ACLPermission(strings.ToUpper(strings.TrimSpace(string(g.Permission))))
	switch p {
	case ACLPermRead:
		return risk.PermRead
	case ACLPermWrite:
		return risk.PermWrite
	case ACLPermReadACP:
		return risk.PermAdminRead
	case ACLPermWriteACP:
		return risk.PermAdminWrite
	case ACLPermFullControl:
		return risk.PermRead | risk.PermWrite | risk.PermAdminRead | risk.PermAdminWrite
	default:
		return 0
	}
}
