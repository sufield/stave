// Package sanitize provides deterministic sanitization of infrastructure
// identifiers from Stave CLI output. Same input always produces the same
// sanitized token.
package sanitize

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/platform/crypto"
)

// messagePathRe matches absolute POSIX-style paths embedded inside free-form
// strings (e.g. wrapped error messages), capturing the basename as group 1.
// messagePathRe alternates: branch 1 matches a URL (kept verbatim);
// branch 2 matches an absolute path with a captured basename. The
// alternation lets ScrubMessage pass URLs through unchanged while
// still scrubbing credential-style paths. The earlier shape was
// path-only, which corrupted URLs like `http://example.com/secret`
// into `http://example.comsecret` — the `/secret` was matched and
// replaced, eating the slash that separated host from path.
//
// Single-component absolute paths (e.g. `/secret`) match too — the
// previous shape required at least one intermediate directory and
// let those slip through, which is the exact form a leaked secret-
// token filename takes in error messages from CI runners that mount
// tokens at the root.
// The third alternative `/(?:[^\s:]+/)+` catches paths that end with
// a trailing slash — e.g. `/run/secrets/` or `/var/run/keys/` — which
// the previous two-branch regex left untouched because it required a
// non-slash terminal segment. Trailing-slash paths show up in error
// messages whenever a tool prints a directory rather than a file
// (mount points, container volumes); leaking those is the same
// disclosure as leaking the file path itself.
var messagePathRe = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.\-]*://[^\s]+)|/(?:[^\s:]+/)*([^\s:/]+)|(/(?:[^\s:]+/)+)`)

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

// ScrubMessage replaces absolute paths in a free-form string (e.g. an
// error message) with their basenames.
//
// PathMode no longer gates this redaction. PathFull is about how
// the operator-supplied paths render in user-facing output; it is
// not about whether credentials embedded in error messages get
// scrubbed. The previous shape conflated the two and let secrets
// like `/secret/token` slip through whenever the operator had set
// `--path-mode=full` for any other reason. Credential-style paths
// in error messages are always reduced to their basename.
//
// If a future caller needs fine-grained control (e.g. "I'm in dev
// and want full paths in error messages too"), add a separate
// ScrubCredentialPaths flag rather than re-tying this to PathMode.
func (s *Sanitizer) ScrubMessage(msg string) string {
	if msg == "" {
		return msg
	}
	return messagePathRe.ReplaceAllStringFunc(msg, func(match string) string {
		// Re-match to recover capture groups: ReplaceAllStringFunc
		// gives only the full match, so we have to ask the regex
		// for sub-groups against the same input slice.
		groups := messagePathRe.FindStringSubmatch(match)
		// groups[1] is the URL branch, groups[2] is the
		// credential-style path's terminal segment, groups[3] is
		// the trailing-slash directory branch (e.g. /run/secrets/).
		// Exactly one is non-empty per match because the
		// alternation is mutually exclusive at the top level.
		if len(groups) > 1 && groups[1] != "" {
			return groups[1] // URL — preserve verbatim
		}
		if len(groups) > 2 && groups[2] != "" {
			return groups[2] // credential-style path — keep basename only
		}
		if len(groups) > 3 && groups[3] != "" {
			// Trailing-slash directory: leak the directory name
			// itself the same way credential paths leak the
			// filename. Reduce to the last named segment so
			// "/run/secrets/" still surfaces "secrets" for triage
			// without exposing the surrounding mount-point chain.
			trimmed := strings.TrimRight(groups[3], "/")
			if i := strings.LastIndex(trimmed, "/"); i >= 0 {
				return trimmed[i+1:] + "/"
			}
			return trimmed + "/"
		}
		return match
	})
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
			// When the value itself is a nested map / list, keep
			// applying the Profile rules at deeper levels so a child
			// key still in the Remove set drops out and a child key
			// still in the Sanitize set is redacted at value level —
			// rather than blanket-scrubbing the whole subtree's
			// scalar values uniformly.
			out[k] = s.scrubValueWithProfile(v, profile)
			continue
		}
		if nested, ok := v.(map[string]any); ok {
			out[k] = s.ScrubMap(nested, profile)
			continue
		}
		if list, ok := v.([]any); ok {
			// Neutral-parent path: scalars preserved.
			out[k] = s.scrubList(list, profile, false)
			continue
		}
		out[k] = v
	}
	return out
}

// scrubList recurses into list elements, scrubbing nested maps/lists
// with the same profile.
//
// When inSanitizedScope is false (the default — the caller hit a
// neutral parent key), scalar elements are preserved as-is because
// the profile is keyed by map property name and does not classify
// list elements directly. When inSanitizedScope is true (the caller
// reached this list via a Sanitize-flagged parent key), scalar
// strings are replaced with their per-value scrub form so a list
// of secret tokens does not leak through just because the values
// happen to be string scalars rather than nested maps.
func (s *Sanitizer) scrubList(list []any, profile Profile, inSanitizedScope bool) []any {
	if list == nil {
		return nil
	}
	out := make([]any, len(list))
	for i, item := range list {
		switch v := item.(type) {
		case map[string]any:
			out[i] = s.ScrubMap(v, profile)
		case []any:
			out[i] = s.scrubList(v, profile, inSanitizedScope)
		case string:
			if inSanitizedScope && v != "" {
				out[i] = "SANITIZED_" + crypto.ShortToken(v)
			} else {
				out[i] = item
			}
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

// scrubValueWithProfile redacts a property's value while preserving
// its underlying type so downstream JSON consumers see the same
// shape they would for an unredacted property. String values are
// deterministically hashed; numeric and boolean primitives are
// zeroed. Containers recurse with the same Profile so nested Remove
// rules apply through every layer — including beneath a
// Sanitize-flagged parent, which the earlier "swap to scrubValue
// for the empty-profile path" version silently bypassed.
//
// Profile-driven scrubbing is independent of the sanitizeIDs flag:
// by the time this runs, ScrubMap has already determined the key is
// in the profile's Sanitize set, so the value is always redacted —
// a zero-value Sanitizer (sanitizeIDs=false) still strips values
// whose property names are profile-classified as sensitive.
func (s *Sanitizer) scrubValueWithProfile(v any, profile Profile) any {
	switch val := v.(type) {
	case nil:
		return nil
	case string:
		if val == "" {
			return val
		}
		return "SANITIZED_" + crypto.ShortToken(val)
	case bool:
		// Scrub bools to their zero value (false) so the JSON output
		// keeps its declared type. The earlier shape returned the
		// SanitizedValue *string* here, which silently broke
		// schema-typed JSON consumers — a field declared as a bool
		// in out.v0.1.json suddenly contained `"[SANITIZED]"`,
		// failing schema validation and downstream type assertions.
		// The privacy concern that drove the string output ("a
		// scrubbed false is indistinguishable from a legitimate
		// false") is real but secondary to the type-safety break;
		// callers that need to distinguish "redacted" vs "really
		// false" should set the parent map key to a Sanitize-flagged
		// path so the value is removed entirely, or wrap the bool
		// in a typed sentinel struct.
		//
		// IMPORTANT: this means a sanitized output of a bool field is
		// not distinguishable from a legitimate `false`. Pipelines
		// that *re-ingest* sanitized output (a sanitized snapshot
		// becoming an input to another stave run, for example) MUST
		// treat bool fields as untrusted: a sanitized `true` becomes
		// `false` after the round trip, which can flip a control's
		// verdict. Treat sanitization as a one-way operation toward
		// human consumers, not an idempotent transform.
		return false
	case int:
		return 0
	case int8:
		return int8(0)
	case int16:
		return int16(0)
	case int32:
		return int32(0)
	case int64:
		return int64(0)
	case uint:
		return uint(0)
	case uint8:
		return uint8(0)
	case uint16:
		return uint16(0)
	case uint32:
		return uint32(0)
	case uint64:
		return uint64(0)
	case float32:
		return float32(0)
	case float64:
		return float64(0)
	case json.Number:
		return json.Number("0")
	case time.Time:
		// Zero time so the redacted JSON keeps its declared type.
		// Scrubbing a timestamp to a string sentinel would fail
		// schema validation on consumers expecting RFC3339.
		return time.Time{}
	case json.RawMessage:
		// Raw JSON byte slice. Replace with a JSON null so consumers
		// that re-encode get a structurally-valid placeholder, not
		// a malformed payload.
		return json.RawMessage("null")
	case []any:
		// scrubValueWithProfile fires when a Sanitize-flagged parent
		// reached a list value, so propagate inSanitizedScope=true
		// to scrubList. That way scalar strings in the list — which
		// scrubList's neutral path leaves alone — get the same
		// per-value scrub treatment that nested maps would get.
		return s.scrubList(val, profile, true)
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, sub := range val {
			if profile.ShouldRemove(k) {
				continue
			}
			if profile.ShouldSanitize(k) {
				// Recurse with profile context so nested Remove
				// keys still apply through a Sanitize-flagged
				// parent. The earlier shape called s.scrubValue
				// here, which lost the profile and let
				// "tags-removable" entries leak through if a
				// Sanitize key sat above them in the tree.
				out[k] = s.scrubValueWithProfile(sub, profile)
				continue
			}
			// Neutral key: the key itself isn't classified, so the
			// scalar value at this slot is data the operator wants
			// to read. Preserve primitives as-is. Only recurse into
			// containers, where deeper keys may match Remove or
			// Sanitize. The earlier shape recursed unconditionally,
			// which scrubbed primitive scalars under non-classified
			// keys (every plain string became `SANITIZED_<hash>`).
			switch sub.(type) {
			case map[string]any, []any:
				out[k] = s.scrubValueWithProfile(sub, profile)
			default:
				out[k] = sub
			}
		}
		return out
	default:
		// Reached when a leaf value's Go type isn't covered by the
		// switch above. Numbers, booleans, time stamps, and JSON
		// raw messages have dedicated cases; arriving here means a
		// new type leaked into the activation map (a custom struct
		// from a producer, a typed alias, etc.). Log so the gap is
		// visible — silently sentinelling an unknown type can hide
		// a real schema drift between producer and engine.
		slog.Warn("sanitize: unknown leaf type, emitting SANITIZED_UNKNOWN_TYPE sentinel",
			"go_type", fmt.Sprintf("%T", v))
		// Sentinel string lets a downstream parser distinguish
		// "engine reached a type it didn't classify" from "the
		// value was nil"; the JSON-type cost (an int field becomes
		// a string) is accepted for triage visibility.
		return "SANITIZED_UNKNOWN_TYPE"
	}
}
