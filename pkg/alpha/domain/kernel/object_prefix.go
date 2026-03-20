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
	if !strings.HasSuffix(scope, "/") {
		scope += "/"
	}
	t := string(target)
	if !strings.HasSuffix(t, "/") {
		t += "/"
	}
	return strings.HasPrefix(t, scope)
}
