package exposure

import "github.com/sufield/stave/internal/domain/kernel"

// VisibilityResult captures post-PAB effective visibility plus pre-PAB source signals.
type VisibilityResult struct {
	PublicRead                      bool `json:"public_read"`
	PublicList                      bool `json:"public_list"`
	PublicWrite                     bool `json:"public_write"`
	PublicReadViaPolicy             bool `json:"public_read_via_policy"`
	PublicReadViaACL                bool `json:"public_read_via_acl"`
	PublicListViaPolicy             bool `json:"public_list_via_policy"`
	PublicWriteViaACL               bool `json:"public_write_via_acl"`
	AuthenticatedUsersRead          bool `json:"authenticated_users_read"`
	AuthenticatedUsersWrite         bool `json:"authenticated_users_write"`
	PublicACLWritable               bool `json:"public_acl_writable"`
	AuthenticatedUsersACLWritable   bool `json:"authenticated_users_acl_writable"`
	PublicACLReadable               bool `json:"public_acl_readable"`
	AuthenticatedUsersACLReadable   bool `json:"authenticated_users_acl_readable"`
	LatentPublicRead                bool `json:"latent_public_read"`
	LatentPublicList                bool `json:"latent_public_list"`
	PolicyExposureBlocked           bool `json:"-"`
	ACLExposureBlocked              bool `json:"-"`
	HasFullControlPublic            bool `json:"-"`
	HasFullControlAuthenticatedOnly bool `json:"-"`
}

// EffectiveVisibility is the resolver output before storage/output projection.
type EffectiveVisibility struct {
	Read           bool
	Write          bool
	List           bool
	ACLRead        bool
	ACLWrite       bool
	Source         string
	IsLatent       bool
	PrincipalScope kernel.PrincipalScope
}

// IsPublic returns true when any access channel is effectively public.
func (v EffectiveVisibility) IsPublic() bool {
	return v.Read || v.Write || v.List || v.ACLRead || v.ACLWrite
}
