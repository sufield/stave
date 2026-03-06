// Package sanitize — OutputSanitizationPolicy centralizes sanitization configuration.
package sanitize

import "strings"

// PathMode controls how file paths are rendered in user-facing output.
type PathMode string

const (
	// PathModeFull renders absolute paths as-is.
	PathModeFull PathMode = "full"
	// PathModeBase renders only the basename of each path.
	PathModeBase PathMode = "base"
)

// ParsePathMode parses a string to a PathMode, defaulting to PathModeBase.
func ParsePathMode(s string) PathMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case string(PathModeFull):
		return PathModeFull
	default:
		return PathModeBase
	}
}

// OutputSanitizationPolicy bundles all output sanitization settings.
// It is constructed once from CLI flags and threaded through commands,
// writers, error formatting, and the panic handler.
type OutputSanitizationPolicy struct {
	// SanitizeIDs enables deterministic sanitization of resource identifiers,
	// matched property values, and source evidence in findings output.
	SanitizeIDs bool

	// PathMode controls rendering of file paths in errors and logs.
	// "base" (default) strips directory prefixes; "full" preserves them.
	PathMode PathMode
}

// Sanitizer returns a functional sanitizer.
// When SanitizeIDs is false, it returns a no-op sanitizer.
func (p OutputSanitizationPolicy) Sanitizer() *Sanitizer {
	if p.SanitizeIDs {
		return New()
	}
	return NewNoOp()
}

// ShouldSanitizePaths returns true when paths should be shortened to basenames.
func (p OutputSanitizationPolicy) ShouldSanitizePaths() bool {
	return p.PathMode == PathModeBase
}
