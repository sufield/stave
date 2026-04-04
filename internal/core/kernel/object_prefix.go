package kernel

import "strings"

// ObjectPrefix represents a normalized S3 object key prefix used for scope matching.
// Examples: "*" (wildcard, matches all), "invoices/", "data/secrets/".
type ObjectPrefix string

// WildcardPrefix matches all object keys.
const WildcardPrefix ObjectPrefix = "*"

// String returns the raw prefix string.
func (p ObjectPrefix) String() string {
	return string(p)
}

// EnsureTrailingSlash returns s with a trailing "/" appended if not already present.
func EnsureTrailingSlash(s string) string {
	if !strings.HasSuffix(s, "/") {
		return s + "/"
	}
	return s
}

// Matches reports whether this prefix (acting as a scope) covers the target prefix.
// A wildcard scope matches everything. Otherwise, the scope must be an ancestor
// directory of the target (compared with trailing-slash normalization).
func (p ObjectPrefix) Matches(target ObjectPrefix) bool {
	scope := strings.TrimSpace(string(p))
	if scope == "" {
		return false
	}
	if scope == "*" {
		return true
	}
	scope = EnsureTrailingSlash(scope)
	t := EnsureTrailingSlash(string(target))
	return strings.HasPrefix(t, scope)
}
