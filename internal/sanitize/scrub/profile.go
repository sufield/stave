// Package scrub provides snapshot-level scrubbing of sensitive data.
// It applies scrub profiles to observation snapshots before persistence
// or display, removing or sanitizing sensitive property values.
package scrub

// ScrubProfile defines which property keys to remove or sanitize during scrubbing.
type ScrubProfile struct {
	RemovedKeys   map[string]struct{}
	SanitizedKeys map[string]struct{}
}

// DefaultAssetProfile is the default scrub profile for asset properties.
// Sensitive keys (tags, policy, ACL) are removed; identifying keys (bucket_name,
// arn) are replaced with deterministic tokens.
var DefaultAssetProfile = ScrubProfile{
	RemovedKeys: map[string]struct{}{
		"tags":                     {},
		"policy":                   {},
		"policy_json":              {},
		"policy_public_statements": {},
		"acl_grants":               {},
		"acl_public_grantees":      {},
	},
	SanitizedKeys: map[string]struct{}{
		"bucket_name": {},
		"arn":         {},
	},
}

// DefaultIdentityProfile is the default scrub profile for identity properties.
var DefaultIdentityProfile = ScrubProfile{
	RemovedKeys: map[string]struct{}{
		"owner":   {},
		"purpose": {},
	},
}
