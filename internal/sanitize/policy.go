// Package sanitize centralizes output sanitization configuration.
package sanitize

// PathMode controls how file paths are rendered in user-facing output.
type PathMode string

const (
	// PathBase (zero value) renders only the basename of each path.
	PathBase PathMode = ""
	// PathFull renders paths as provided.
	PathFull PathMode = "full"
)

// Option configures a Sanitizer during construction.
type Option func(*Sanitizer)

// WithPathMode sets the path rendering strategy.
func WithPathMode(m PathMode) Option {
	return func(s *Sanitizer) {
		s.pathMode = m
	}
}

// WithIDSanitization enables or disables asset identifier sanitization.
func WithIDSanitization(enabled bool) Option {
	return func(s *Sanitizer) {
		s.sanitizeIDs = enabled
	}
}

// Policy bundles output sanitization settings.
// Constructed once from CLI flags and threaded through commands.
type Policy struct {
	// SanitizeIDs enables deterministic sanitization of asset identifiers,
	// matched property values, and source evidence in findings output.
	SanitizeIDs bool

	// PathMode controls rendering of file paths in errors and logs.
	// Zero value (PathBase) strips directory prefixes; PathFull preserves them.
	PathMode PathMode
}

// NewSanitizer returns a sanitizer configured from the policy.
func (p Policy) NewSanitizer() *Sanitizer {
	return New(
		WithPathMode(p.PathMode),
		WithIDSanitization(p.SanitizeIDs),
	)
}
