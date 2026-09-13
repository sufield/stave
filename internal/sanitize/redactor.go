package sanitize

import "github.com/sufield/stave/internal/core/asset"

// Redactor defines the full sanitization capability: identifier
// masking, path shortening, free-form message scrubbing, and
// snapshot-level redaction. Consumers that need the complete
// sanitization surface depend on this interface instead of the
// concrete Sanitizer struct. See kernel.Sanitizer for the narrower
// ID/Path/Value-only contract.
type Redactor interface {
	ID(string) string
	Path(string) string
	Value(string) string
	ScrubMessage(string) string
	Snapshot(asset.Snapshot) asset.Snapshot
}

var _ Redactor = (*Sanitizer)(nil)
