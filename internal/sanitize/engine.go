// Package sanitize provides deterministic sanitization of infrastructure
// identifiers from Stave CLI output. Same input always produces the same
// sanitized token.
package sanitize

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/platform/crypto"
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

// Value sanitizes an arbitrary string value. Two distinct values produce
// two distinct deterministic tokens, so equality of redacted output still
// reflects equality of the original input.
func (s *Sanitizer) Value(v string) string {
	if s == nil || !s.sanitizeIDs || v == "" {
		return v
	}
	return "SANITIZED_" + crypto.ShortToken(v)
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

// --- Snapshot-level scrubbing ---

// Snapshot returns a copy of the snapshot with sensitive properties removed.
// Retains boolean fields needed for evaluation, removes raw policy/ACL/tag data.
func (s *Sanitizer) Snapshot(snap asset.Snapshot) asset.Snapshot {
	if s == nil {
		return snap
	}
	out := asset.Snapshot{
		SchemaVersion: snap.SchemaVersion,
		GeneratedBy:   snap.GeneratedBy,
		CapturedAt:    snap.CapturedAt,
	}
	out.Assets = make([]asset.Asset, len(snap.Assets))
	for i, a := range snap.Assets {
		out.Assets[i] = s.scrubAsset(a)
	}
	if len(snap.Identities) > 0 {
		out.Identities = make([]asset.CloudIdentity, len(snap.Identities))
		for i, id := range snap.Identities {
			out.Identities[i] = s.scrubIdentity(id)
		}
	}
	return out
}

// ScrubMap returns a deep copy of a properties map with keys removed or
// sanitized according to the profile. Nested maps and lists are recursed
// so sensitive values nested inside list-shaped properties are still scrubbed.
func (s *Sanitizer) ScrubMap(props map[string]any, profile Profile) map[string]any {
	if props == nil {
		return nil
	}
	out := make(map[string]any, len(props))
	for k, v := range props {
		if profile.ShouldRemove(k) {
			continue
		}
		if profile.ShouldSanitize(k) {
			out[k] = s.scrubValue(v)
			continue
		}
		if nested, ok := v.(map[string]any); ok {
			out[k] = s.ScrubMap(nested, profile)
			continue
		}
		if list, ok := v.([]any); ok {
			out[k] = s.scrubList(list, profile)
			continue
		}
		out[k] = v
	}
	return out
}

// scrubList recurses into list elements, scrubbing nested maps/lists with
// the same profile. Non-container elements are kept as-is — the profile is
// keyed by map property name and does not classify list elements directly.
func (s *Sanitizer) scrubList(list []any, profile Profile) []any {
	if list == nil {
		return nil
	}
	out := make([]any, len(list))
	for i, item := range list {
		switch v := item.(type) {
		case map[string]any:
			out[i] = s.ScrubMap(v, profile)
		case []any:
			out[i] = s.scrubList(v, profile)
		default:
			out[i] = item
		}
	}
	return out
}

func (s *Sanitizer) scrubAsset(a asset.Asset) asset.Asset {
	return asset.Asset{
		ID:         asset.ID(s.ID(string(a.ID))),
		Type:       a.Type,
		Vendor:     a.Vendor,
		Source:     s.scrubSource(a.Source),
		Properties: s.ScrubMap(a.Properties, AssetProfile()),
	}
}

func (s *Sanitizer) scrubIdentity(id asset.CloudIdentity) asset.CloudIdentity {
	return asset.CloudIdentity{
		ID:         asset.ID(s.ID(string(id.ID))),
		Type:       id.Type,
		Vendor:     id.Vendor,
		Source:     s.scrubSource(id.Source),
		Properties: s.ScrubMap(id.Properties, IdentityProfile()),
	}
}

func (s *Sanitizer) scrubSource(src *asset.SourceRef) *asset.SourceRef {
	if src == nil {
		return nil
	}
	return &asset.SourceRef{
		File: s.Path(src.File),
		Line: src.Line,
	}
}

// scrubValue redacts a sanitized property's value while preserving its
// underlying type so downstream JSON consumers see the same shape they
// would for an unredacted property. String values are deterministically
// hashed; numeric and boolean primitives are zeroed; containers recurse.
func (s *Sanitizer) scrubValue(v any) any {
	switch val := v.(type) {
	case nil:
		return nil
	case string:
		return s.ID(val)
	case bool:
		return false
	case int:
		return 0
	case int32:
		return int32(0)
	case int64:
		return int64(0)
	case float32:
		return float32(0)
	case float64:
		return float64(0)
	case []any:
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = s.scrubValue(item)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, sub := range val {
			out[k] = s.scrubValue(sub)
		}
		return out
	default:
		return SanitizedValue
	}
}
