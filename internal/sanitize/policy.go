// Package sanitize — Policy centralizes output sanitization configuration.
package sanitize

// PathMode controls how file paths are rendered in user-facing output.
type PathMode string

const (
	// PathBase (default) renders only the basename of each path.
	PathBase PathMode = "base"
	// PathFull renders absolute paths as-is.
	PathFull PathMode = "full"
)

// Effective returns the mode, defaulting to PathBase when unset.
// This handles the zero-value case where PathMode is "".
func (m PathMode) Effective() PathMode {
	if m == PathFull {
		return PathFull
	}
	return PathBase
}

// Policy bundles all output sanitization settings.
// It is constructed once from CLI flags and threaded through commands,
// writers, error formatting, and the panic handler.
type Policy struct {
	// SanitizeIDs enables deterministic sanitization of asset identifiers,
	// matched property values, and source evidence in findings output.
	SanitizeIDs bool

	// PathMode controls rendering of file paths in errors and logs.
	// "base" (default) strips directory prefixes; "full" preserves them.
	PathMode PathMode
}

// NewSanitizer returns a configured sanitizer based on the policy.
// When SanitizeIDs is false, ID/value sanitization is disabled but
// path mode is still respected.
func (p Policy) NewSanitizer() *Sanitizer {
	s := New()
	s.pathMode = p.PathMode.Effective()
	if !p.SanitizeIDs {
		s.disableIDs = true
	}
	return s
}
