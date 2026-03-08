package kernel

// Sanitizer provides primitive sanitization operations for output.
// Domain types accept this interface to sanitize themselves without
// importing the concrete sanitize package.
type Sanitizer interface {
	ID(id string) string
	Path(p string) string
	Value(v string) string
}

// IDSanitizer is the narrow interface for replacing identifiers with
// deterministic tokens. Any Sanitizer implementation satisfies this.
type IDSanitizer interface {
	ID(string) string
}

// PathSanitizer is the narrow interface for shortening file paths in output.
// Any Sanitizer implementation satisfies this.
type PathSanitizer interface {
	Path(string) string
}
