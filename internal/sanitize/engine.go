// Package sanitize provides deterministic sanitization of infrastructure identifiers
// from Stave CLI output. Same input always produces the same sanitized token.
package sanitize

import (
	"path/filepath"
	"regexp"

	"github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

// messagePathRe matches absolute POSIX-style paths embedded inside free-form
// strings (e.g. wrapped error messages), capturing the basename as group 1.
var messagePathRe = regexp.MustCompile(`/(?:[^\s:]+/)+([^\s:/]+)`)

// Compile-time check that Sanitizer implements kernel.Sanitizer.
var _ kernel.Sanitizer = (*Sanitizer)(nil)

// Sanitizer sanitizes infrastructure identifiers from output.
// It is deterministic: the same input value always produces the same token.
type Sanitizer struct {
	disableIDs bool
	pathMode   PathMode
}

// New creates a new Sanitizer with default path mode.
func New() *Sanitizer {
	return &Sanitizer{pathMode: PathBase}
}

// idEnabled reports whether ID/asset/value sanitization is active.
func (s *Sanitizer) idEnabled() bool {
	return s != nil && !s.disableIDs
}

// pathEnabled reports whether path-stripping logic should be applied.
func (s *Sanitizer) pathEnabled() bool {
	return s != nil && s.pathMode.Effective() == PathBase
}

// hash generates a deterministic 8-hex-char token from a value.
func (s *Sanitizer) hash(val string) string {
	return crypto.ShortToken(val)
}

// ID sanitizes a plain string identifier. Implements kernel.Sanitizer.
func (s *Sanitizer) ID(id string) string {
	if !s.idEnabled() || id == "" {
		return id
	}
	return string(asset.ID(id).Sanitize(s.hash))
}

// Asset sanitizes an asset identifier.
// Delegates to AssetID.Sanitize (Tell, Don't Ask).
func (s *Sanitizer) Asset(id asset.ID) asset.ID {
	if !s.idEnabled() {
		return id
	}
	return id.Sanitize(s.hash)
}

// Value sanitizes an arbitrary string value.
func (s *Sanitizer) Value(v string) string {
	if !s.idEnabled() {
		return v
	}
	return "[SANITIZED]"
}

// Path sanitizes a file path according to the configured PathMode.
// PathFull returns the path as-is; PathBase strips to the basename.
func (s *Sanitizer) Path(p string) string {
	if !s.pathEnabled() {
		return p
	}
	return filepath.Base(p)
}

// ScrubMessage replaces absolute paths in a free-form string (e.g. an error
// message) with their basenames. Returns the message unchanged when path
// sanitization is inactive.
func (s *Sanitizer) ScrubMessage(msg string) string {
	if !s.pathEnabled() || msg == "" {
		return msg
	}
	return messagePathRe.ReplaceAllString(msg, "$1")
}
