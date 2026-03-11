// Package sanitize provides deterministic sanitization of infrastructure identifiers
// from Stave CLI output. Same input always produces the same sanitized token.
package sanitize

import (
	"path/filepath"
	"regexp"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/platform/crypto"
)

// messagePathRe matches absolute POSIX-style paths embedded inside free-form
// strings (e.g. wrapped error messages), capturing the basename as group 1.
var messagePathRe = regexp.MustCompile(`/(?:[^\s:]+/)+([^\s:/]+)`)

// Compile-time check that Sanitizer implements kernel.Sanitizer.
var _ kernel.Sanitizer = (*Sanitizer)(nil)

// Sanitizer sanitizes infrastructure identifiers from output.
// It is deterministic: the same input value always produces the same token.
type Sanitizer struct {
	noOp          bool
	pathMode      PathMode
	resourceScrub ScrubConfig
	identityScrub ScrubConfig
}

// New creates a new Sanitizer with default scrub configs.
func New() *Sanitizer {
	return &Sanitizer{
		pathMode:      PathModeBase,
		resourceScrub: DefaultAssetScrub,
		identityScrub: DefaultIdentityScrub,
	}
}

// NewNoOp creates a sanitizer that performs no transformations.
func NewNoOp() *Sanitizer {
	return &Sanitizer{
		noOp:          true,
		pathMode:      PathModeBase,
		resourceScrub: DefaultAssetScrub,
		identityScrub: DefaultIdentityScrub,
	}
}

func (r *Sanitizer) enabled() bool {
	return r != nil && !r.noOp
}

// token generates a deterministic 8-hex-char token from a value.
func (r *Sanitizer) token(val string) string {
	return crypto.ShortToken(val)
}

// ID sanitizes a plain string identifier. Implements kernel.Sanitizer.
func (r *Sanitizer) ID(id string) string {
	if !r.enabled() || id == "" {
		return id
	}
	return string(asset.ID(id).Sanitize(r.token))
}

// Asset sanitizes an asset identifier.
// Delegates to AssetID.Sanitize (Tell, Don't Ask).
func (r *Sanitizer) Asset(id asset.ID) asset.ID {
	if !r.enabled() {
		return id
	}
	return id.Sanitize(r.token)
}

// sanitizeAssetID is the string-level adapter used by free-text sanitization
// (scrubProperties) where the input is a raw string.
func (r *Sanitizer) sanitizeAssetID(raw string) string {
	return string(asset.ID(raw).Sanitize(r.token))
}

// Value sanitizes an arbitrary string value.
func (r *Sanitizer) Value(v string) string {
	if !r.enabled() {
		return v
	}
	return "[SANITIZED]"
}

// Path sanitizes a file path according to the configured PathMode.
// PathModeFull returns the path as-is; PathModeBase strips to the basename.
func (r *Sanitizer) Path(p string) string {
	if !r.enabled() || r.pathMode == PathModeFull {
		return p
	}
	return filepath.Base(p)
}

// ScrubMessage replaces absolute paths in a free-form string (e.g. an error
// message) with their basenames. Returns the message unchanged when path
// sanitization is inactive.
func (r *Sanitizer) ScrubMessage(msg string) string {
	if r == nil || r.pathMode == PathModeFull {
		return msg
	}
	return messagePathRe.ReplaceAllString(msg, "$1")
}

// Bucket sanitizes a bucket name for enforcement artifacts.
func (r *Sanitizer) Bucket(name string) string {
	if !r.enabled() {
		return name
	}
	return "SANITIZED_" + r.token(name)
}

// Verification sanitizes an asset ID in a verification entry.
func (r *Sanitizer) Verification(assetID asset.ID) asset.ID {
	return r.Asset(assetID)
}
