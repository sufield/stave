// Package scrub provides snapshot-level scrubbing of sensitive data.
// It applies scrub profiles to observation snapshots before persistence
// or display, removing or sanitizing sensitive property values.
package scrub

// Profile defines which property keys to remove or sanitize during scrubbing.
type Profile struct {
	Remove   map[string]struct{}
	Sanitize map[string]struct{}
}

// ShouldRemove reports whether the key is marked for removal.
func (p Profile) ShouldRemove(key string) bool {
	if p.Remove == nil {
		return false
	}
	_, ok := p.Remove[key]
	return ok
}

// ShouldSanitize reports whether the key is marked for sanitization.
func (p Profile) ShouldSanitize(key string) bool {
	if p.Sanitize == nil {
		return false
	}
	_, ok := p.Sanitize[key]
	return ok
}

// AssetProfile returns the default scrub profile for asset properties.
// Returns a fresh copy to prevent callers from mutating shared state.
func AssetProfile() Profile {
	return Profile{
		Remove: map[string]struct{}{
			"tags":                     {},
			"policy":                   {},
			"policy_json":              {},
			"policy_public_statements": {},
			"acl_grants":               {},
			"acl_public_grantees":      {},
		},
		Sanitize: map[string]struct{}{
			"bucket_name": {},
			"arn":         {},
		},
	}
}

// IdentityProfile returns the default scrub profile for identity properties.
func IdentityProfile() Profile {
	return Profile{
		Remove: map[string]struct{}{
			"owner":   {},
			"purpose": {},
		},
		Sanitize: make(map[string]struct{}),
	}
}
