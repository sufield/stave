package kernel

// Sanitizer provides primitive sanitization operations for output.
// Domain types accept this interface to sanitize themselves without
// importing the concrete sanitize package.
type Sanitizer interface {
	ID(id string) string
	Path(p string) string
	Value(v string) string
}
