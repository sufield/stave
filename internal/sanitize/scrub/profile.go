// Package scrub provides snapshot-level scrubbing of sensitive data.
// It applies scrub profiles to observation snapshots before persistence
// or display, removing or sanitizing sensitive property values.
//
// This package also serves as the single source of truth for what constitutes
// "sensitive data" across the entire CLI: credential patterns, sensitive flag
// names, and property keys are all defined here and imported by the logging
// and bug-report subsystems.
package scrub

import "regexp"

// SanitizedValue is the canonical placeholder for redacted values.
const SanitizedValue = "[SANITIZED]"

// --- Credential patterns (used by bug-report log scrubbing) ---

// AKIAPattern matches AWS access key IDs embedded in text.
var AKIAPattern = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)

// URLCredPattern matches credentials embedded in URLs (user:pass@host).
var URLCredPattern = regexp.MustCompile(`(?i)(https?://[^/\s:@]+:)[^@/\s]+@`)

// --- Sensitive flag/key detection (used by logging argument sanitization) ---

// SensitiveArgNames are complete flag names (normalized, lowercase) known to
// carry sensitive values.
var SensitiveArgNames = map[string]struct{}{
	"private_key":          {},
	"private_key_out":      {},
	"integrity_public_key": {},
	"public_key_out":       {},
	"authorization":        {},
}

// SensitiveTokens are individual words that mark a compound flag name as
// sensitive when they appear as a discrete segment (split on _-.:).
var SensitiveTokens = map[string]struct{}{
	"token":      {},
	"secret":     {},
	"password":   {},
	"credential": {},
	"auth":       {},
	"bearer":     {},
	"key":        {},
}

// --- Property scrub profiles (used by snapshot scrubbing) ---

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
			"external_id": {},
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
