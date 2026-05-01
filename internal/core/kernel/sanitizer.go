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

// MessageSanitizer scrubs free-form strings (log messages, error text)
// of paths, IDs, and other identifiers. Implemented by *sanitize.Sanitizer.
//
// The interface lives in kernel because consumers (logger middleware,
// error formatters) belong outside sanitize and need a kernel-level
// type to depend on without pulling the full sanitize package.
type MessageSanitizer interface {
	ScrubMessage(msg string) string
}

// Sanitizer aggregates the primitive ID/Path/Value sanitization operations.
// Domain objects typically accept this interface to prepare themselves for
// public output. MessageSanitizer is intentionally NOT embedded here:
// most consumers only need ID/Path/Value, and forcing every test stub to
// implement ScrubMessage adds noise. Callers that need free-form string
// scrubbing should depend on MessageSanitizer directly (ISP).
type Sanitizer interface {
	IDSanitizer
	PathSanitizer
	ValueSanitizer
}
