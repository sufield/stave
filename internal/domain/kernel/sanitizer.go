package kernel

// IDSanitizer defines the capability to mask identifiers with deterministic tokens.
type IDSanitizer interface {
	ID(id string) string
}

// PathSanitizer defines the capability to mask or shorten file paths in output.
type PathSanitizer interface {
	Path(p string) string
}

// ValueSanitizer defines the capability to mask general string values.
type ValueSanitizer interface {
	Value(v string) string
}

// Sanitizer aggregates all primitive sanitization operations.
// Domain objects typically accept this interface to prepare themselves for public output.
type Sanitizer interface {
	IDSanitizer
	PathSanitizer
	ValueSanitizer
}
