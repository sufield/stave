// Package sanitize — OutputSanitizationPolicy centralizes sanitization configuration.
package sanitize

// PathMode controls how file paths are rendered in user-facing output.
type PathMode string

const (
	// PathModeFull renders absolute paths as-is.
	PathModeFull PathMode = "full"
	// PathModeBase renders only the basename of each path.
	PathModeBase PathMode = "base"
)

// OutputSanitizationPolicy bundles all output sanitization settings.
// It is constructed once from CLI flags and threaded through commands,
// writers, error formatting, and the panic handler.
type OutputSanitizationPolicy struct {
	// SanitizeIDs enables deterministic sanitization of asset identifiers,
	// matched property values, and source evidence in findings output.
	SanitizeIDs bool

	// PathMode controls rendering of file paths in errors and logs.
	// "base" (default) strips directory prefixes; "full" preserves them.
	PathMode PathMode
}

// Sanitizer returns a configured sanitizer.
// When SanitizeIDs is false, it returns a no-op sanitizer.
// PathMode is always injected so that Path() respects the user's preference.
func (p OutputSanitizationPolicy) Sanitizer() *Sanitizer {
	s := New()
	s.pathMode = p.PathMode
	if !p.SanitizeIDs {
		s.noOp = true
	}
	return s
}
