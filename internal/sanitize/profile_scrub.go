// Package sanitize provides snapshot-level scrubbing of sensitive data.
// It applies scrub profiles to observation snapshots before persistence
// or display, removing or sanitizing sensitive property values.
//
// This package also serves as the single source of truth for what constitutes
// "sensitive data" across the entire CLI: credential patterns, sensitive flag
// names, and property keys are all defined here and imported by the logging
// and bug-report subsystems.
package sanitize

import (
	"regexp"
	"strings"
)

// SanitizedValue is the canonical placeholder for redacted values.
const SanitizedValue = "[SANITIZED]"

// --- Credential patterns (used by bug-report log scrubbing) ---

// AKIAPattern matches AWS access key IDs (AKIA = long-term root /
// IAM user keys; ASIA = STS temporary credentials). The earlier
// shape only matched AKIA, so a leaked STS session token —
// produced by every short-lived credential path including
// AssumeRole, federated logins, and EC2 instance roles — slipped
// through bug-report scrubbing unchanged.
var AKIAPattern = regexp.MustCompile(`A[KS]IA[0-9A-Z]{16}`)

// URLCredPattern matches credentials embedded in URLs (user:pass@host).
// Covers https?, ftp, sftp, ssh, and git (including git+https). The
// earlier https-only shape let `git://user:pass@example.com/repo`
// and `ssh://user:pass@host` slip through bug-report scrubbing,
// even though both are common shapes for embedded credentials in
// CI logs and `git remote -v` output.
var URLCredPattern = regexp.MustCompile(`(?i)((?:https?|ftp|s?ftp|ssh|git(?:\+https)?)://[^/\s:@]+:)[^@/\s]+@`)

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

// NewProfile constructs a Profile whose Remove and Sanitize maps are
// guaranteed to be lowercase-keyed. The lookup helpers
// (ShouldRemove / ShouldSanitize) lowercase the input on every call;
// keeping the storage map in the same canonical form removes a class
// of authoring bugs where a profile literal contained "Tags" or
// "BUCKET_NAME" and silently never matched anything. Callers are
// expected to use this constructor; AssetProfile / IdentityProfile
// already do.
func NewProfile(remove, sanitize map[string]struct{}) Profile {
	return Profile{
		Remove:   lowercaseKeySet(remove),
		Sanitize: lowercaseKeySet(sanitize),
	}
}

func lowercaseKeySet(in map[string]struct{}) map[string]struct{} {
	if in == nil {
		return nil
	}
	out := make(map[string]struct{}, len(in))
	for k := range in {
		out[strings.ToLower(k)] = struct{}{}
	}
	return out
}

// ShouldRemove reports whether the key is marked for removal.
// Match is case-insensitive — extractors that emit `Tags` instead
// of `tags` (a real production drift between cloud SDKs) used to
// slip through because the lookup was exact-case. Lowercasing the
// lookup key matches the canonical-form policy used by the
// SensitiveArgNames map.
func (p Profile) ShouldRemove(key string) bool {
	if p.Remove == nil {
		return false
	}
	lower := strings.ToLower(key)
	_, ok := p.Remove[lower]
	return ok
}

// ShouldSanitize reports whether the key is marked for sanitization.
// See ShouldRemove for the case-insensitivity rationale.
func (p Profile) ShouldSanitize(key string) bool {
	if p.Sanitize == nil {
		return false
	}
	lower := strings.ToLower(key)
	_, ok := p.Sanitize[lower]
	return ok
}

// AssetProfile returns the default scrub profile for asset properties.
// Returns a fresh copy to prevent callers from mutating shared state.
func AssetProfile() Profile {
	return NewProfile(
		map[string]struct{}{
			"tags":                     {},
			"policy":                   {},
			"policy_json":              {},
			"policy_public_statements": {},
			"acl_grants":               {},
			"acl_public_grantees":      {},
		},
		map[string]struct{}{
			"bucket_name": {},
			"external_id": {},
		},
	)
}

// IdentityProfile returns the default scrub profile for identity properties.
func IdentityProfile() Profile {
	return NewProfile(
		map[string]struct{}{
			"owner":   {},
			"purpose": {},
		},
		nil,
	)
}
