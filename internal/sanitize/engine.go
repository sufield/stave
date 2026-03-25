// Package sanitize provides deterministic sanitization of infrastructure
// identifiers from Stave CLI output. Same input always produces the same
// sanitized token.
package sanitize

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

// messagePathRe matches absolute POSIX-style paths embedded inside free-form
// strings (e.g. wrapped error messages), capturing the basename as group 1.
var messagePathRe = regexp.MustCompile(`/(?:[^\s:]+/)+([^\s:/]+)`)

// Compile-time check that Sanitizer implements kernel.Sanitizer.
var _ kernel.Sanitizer = (*Sanitizer)(nil)

// preservedPrefixes lists infrastructure namespaces whose structure is kept
// visible after sanitization. Only the name component following the prefix
// is replaced with a deterministic token.
var preservedPrefixes = []string{
	"arn:aws:s3:::",
}

// Sanitizer applies deterministic sanitization to identifiers and paths.
// The zero value is usable: IDs are not sanitized and paths are stripped
// to basenames (PathBase).
type Sanitizer struct {
	sanitizeIDs bool
	pathMode    PathMode
}

// New returns a Sanitizer configured via functional options.
// The zero value defaults are: IDs not sanitized, paths stripped to basenames.
func New(opts ...Option) *Sanitizer {
	s := &Sanitizer{}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// String implements fmt.Stringer for diagnostic output.
func (s *Sanitizer) String() string {
	if s == nil {
		return "Sanitizer(nil)"
	}
	mode := "base"
	if s.pathMode == PathFull {
		mode = "full"
	}
	return fmt.Sprintf("Sanitizer(ids=%t, path=%s)", s.sanitizeIDs, mode)
}

// ID sanitizes a plain string identifier. Implements kernel.Sanitizer.
func (s *Sanitizer) ID(id string) string {
	if s == nil || !s.sanitizeIDs || id == "" {
		return id
	}
	return s.sanitizeRaw(id)
}

// Asset sanitizes an asset identifier.
func (s *Sanitizer) Asset(id asset.ID) asset.ID {
	if s == nil || !s.sanitizeIDs {
		return id
	}
	return asset.ID(s.sanitizeRaw(id.String()))
}

// Value sanitizes an arbitrary string value.
func (s *Sanitizer) Value(v string) string {
	if s == nil || !s.sanitizeIDs {
		return v
	}
	return "[SANITIZED]"
}

// Path sanitizes a file path according to the configured PathMode.
// PathFull returns the path as-is; PathBase (zero value) strips to basename.
func (s *Sanitizer) Path(p string) string {
	if s != nil && s.pathMode == PathFull {
		return p
	}
	return filepath.Base(p)
}

// ScrubMessage replaces absolute paths in a free-form string (e.g. an error
// message) with their basenames. Returns the message unchanged when path
// mode is PathFull or the message is empty.
func (s *Sanitizer) ScrubMessage(msg string) string {
	if msg == "" || (s != nil && s.pathMode == PathFull) {
		return msg
	}
	return messagePathRe.ReplaceAllString(msg, "$1")
}

// sanitizeRaw applies prefix-aware sanitization to a raw identifier string.
// For each preserved prefix, the first path segment after the prefix is
// tokenised while the rest of the path is kept intact. Identifiers that
// match no prefix become "SANITIZED_<token>".
func (s *Sanitizer) sanitizeRaw(raw string) string {
	if raw == "" {
		return ""
	}
	for _, prefix := range preservedPrefixes {
		if rest, ok := strings.CutPrefix(raw, prefix); ok {
			bucket, path, _ := strings.Cut(rest, "/")
			if path != "" {
				path = "/" + path
			}
			return prefix + "SANITIZED_" + crypto.ShortToken(bucket) + path
		}
	}
	return "SANITIZED_" + crypto.ShortToken(raw)
}
