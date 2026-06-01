// Package sanitize provides deterministic sanitization of infrastructure
// identifiers from Stave CLI output. Same input always produces the same
// sanitized token.
package sanitize

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"reflect"
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
// Trailing-slash paths (e.g. `/run/secrets/`) are handled by the
// basename branch leaving the trailing `/` in place: for
// `failed to read /run/secrets/`, the basename branch matches
// `/run/secrets` and the literal `/` after `secrets` is preserved
// in the output, producing `failed to read secrets/`. A previous
// version added a third regex alternative for the trailing-slash
// case; that alternative was unreachable under RE2's leftmost-
// first matching rule (the basename branch matches at the same
// starting position with non-zero length and wins) AND attempts
// to reorder it ahead of the basename branch caused
// `/home/user/data/obs.json` to mis-match by greedy directory
// consumption. The two-branch form below is the simplest correct
// shape; the trailing-slash test cases below pin that the
// observable output is what operators expect.
var messagePathRe = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.\-]*://[^\s]+)|/(?:[^\s:]+/)*([^\s:/]+)/?`)

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
// Basename-only is intentional: intermediate path segments
// (e.g. `/run/secrets/token` → `/token`) are dropped on purpose because
// the directory layout itself can leak deployment topology — the
// presence of `/run/secrets/` reveals the operator is using a specific
// secrets-management convention, the depth reveals nesting, and the
// sibling sub-paths leak adjacent secret names through autocomplete or
// repeat-error scenarios. Preserving an intermediate marker like
// `/.../basename` would still reveal "this was a multi-segment path",
// which is more than the redaction intends to disclose. If a future
// caller wants to keep more structure, add a separate Scrub mode
// rather than relaxing this default.
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
	if s == nil {
		return msg
	}
	if msg == "" {
		return msg
	}
	return messagePathRe.ReplaceAllStringFunc(msg, func(match string) string {
		// Re-match to recover capture groups: ReplaceAllStringFunc
		// gives only the full match, so we have to ask the regex
		// for sub-groups against the same input slice.
		groups := messagePathRe.FindStringSubmatch(match)
		// groups[1] is the URL branch, groups[2] is the
		// credential-style path's terminal segment. Exactly one is
		// non-empty per match.
		if len(groups) > 1 && groups[1] != "" {
			return groups[1] // URL — preserve verbatim
		}
		if len(groups) > 2 && groups[2] != "" {
			// Credential-style path — preserve the leading slash so
			// the surrounding error message reads grammatically:
			// "open /[BASENAME]: permission denied" rather than
			// "open [BASENAME]: permission denied" which loses the
			// "this is an absolute path" signal. Relative-path
			// matches don't reach this branch (the regex requires
			// the leading "/").
			//
			// Three named leak categories, ordered by specificity.
			// Order is foundational: a single-component
			// trailing-slash path like "/secret/" matches Case 1
			// but would also satisfy isRootLevelFile after stripping
			// the slash — putting Case 1 first ensures the
			// directory-leak treatment wins.
			basename := groups[2]
			trailingSlash := strings.HasSuffix(match, "/")
			isRootLevelFile := match == "/"+basename
			switch {
			case trailingSlash:
				// Case 1: Directory leak (e.g. /run/secrets/).
				// The directory NAME (`secrets`, `keys`, `creds`)
				// is the secret-revealing component, betraying
				// the secret-management convention.
				return "/<redacted>/"
			case isRootLevelFile:
				// Case 2: Direct file leak (e.g. /token).
				// basename equals the entire path, so the
				// basename-retention rule below would round-trip
				// the leaked filename. The package doc cites
				// CI-runner mounted secrets as the canonical
				// shape this case prevents.
				return "/<redacted>"
			default:
				// Case 3: Multi-component path (e.g. /home/user/.ssh/id_rsa).
				// The basename is informational; the intermediate
				// directories are the leak. Keep the basename,
				// strip the directory traversal.
				return "/" + basename
			}
		}
		// The two-branch regex is exhaustive over its alternation,
		// so reaching here would mean the regex matched but no
		// capture group did — typically the result of a regex edit
		// that adds a new alternative without updating the handler.
		// Return [REDACTED] rather than the verbatim match so the
		// failure mode is "scrubbed even though we didn't recognize
		// the form" rather than "leaked because we didn't classify".
		// slog so the gap surfaces during triage.
		slog.Warn("sanitize: ScrubMessage regex matched but no capture group fired; emitting [REDACTED]",
			"match", match)
		return "[REDACTED]"
	})
}

// sanitizeRaw applies prefix-aware sanitization to a raw identifier string.
// For each preserved prefix, the first path segment after the prefix is
// tokenised AND every subsequent path segment is independently tokenised.
// Path structure (segment count, separators) is preserved so debug output
// keeps "this was a 4-segment object key" but no segment carries the
// original content. Identifiers that match no prefix become
// "SANITIZED_<token>".
//
// The earlier shape preserved the path tail verbatim — an S3 ARN like
// `arn:aws:s3:::bucket/customer/12345/secret.json` produced
// `arn:aws:s3:::SANITIZED_<bucket>/customer/12345/secret.json`,
// leaking customer / object-name fragments downstream consumers
// treat as opaque.
func (s *Sanitizer) sanitizeRaw(raw string) string {
	if raw == "" {
		return ""
	}
	for _, prefix := range preservedPrefixes {
		if rest, ok := strings.CutPrefix(raw, prefix); ok {
			bucket, path, _ := strings.Cut(rest, "/")
			scrubbed := prefix + "SANITIZED_" + crypto.ShortToken(bucket)
			if path != "" {
				// Tokenise each path segment independently so empty
				// segments (the "//" pattern in object keys) round-
				// trip as empty strings, preserving structure.
				parts := strings.Split(path, "/")
				for i, p := range parts {
					if p == "" {
						continue
					}
					parts[i] = "SANITIZED_" + crypto.ShortToken(p)
				}
				scrubbed += "/" + strings.Join(parts, "/")
			}
			return scrubbed
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
		// Preserve provenance metadata. Source identifies which
		// extractor / connector produced the snapshot — operators
		// rely on it to trace which AWS account or vendor pipeline
		// surfaced a finding. The earlier shape silently dropped it,
		// so sanitised reports rendered with an empty source field
		// and downstream filters keyed on Source produced empty
		// results.
		Source: snap.Source,
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
	return s.scrubMapInScope(props, profile, false)
}

// scrubMapInScope is the scope-tracking core of ScrubMap. The
// inSanitizedScope flag carries "we're descending under a key the
// profile already classified as Sanitize" through nested
// containers — so a map nested inside a list inside a Sanitize-
// flagged parent still has its scalar values redacted, instead of
// the scope being lost the first time scrubList hands a child map
// back to ScrubMap. The previous shape called ScrubMap directly
// from scrubList, dropping the flag at every list/map alternation.
func (s *Sanitizer) scrubMapInScope(props map[string]any, profile Profile, inSanitizedScope bool) map[string]any {
	if props == nil {
		return nil
	}
	out := make(map[string]any, len(props))
	for k, v := range props {
		if profile.ShouldRemove(k) {
			continue
		}
		// Either the caller's scope already classifies us, or this
		// key opens a new sanitized subtree. Both states route
		// through scrubValueWithProfile, which redacts every
		// scalar and recurses into containers without losing
		// scope.
		if s.isUnderSanitizedScope(inSanitizedScope, k, profile) {
			out[k] = s.scrubValueWithProfile(v, profile)
			continue
		}
		if nested, ok := v.(map[string]any); ok {
			out[k] = s.scrubMapInScope(nested, profile, inSanitizedScope)
			continue
		}
		if list, ok := v.([]any); ok {
			// Neutral-parent path: scalars preserved.
			out[k] = s.scrubList(list, profile, inSanitizedScope)
			continue
		}
		out[k] = v
	}
	return out
}

// isUnderSanitizedScope reports whether the current container
// position should treat every non-removed value as opaque and
// route it through scrubValueWithProfile. True when either the
// caller is already inside a Sanitize-flagged subtree (the flag
// propagated through scrubList / scrubMapInScope) or this key
// itself is classified Sanitize by the profile. Encapsulates the
// "redaction mode" decision so the loop body reads as one
// declarative branch rather than a stack of mechanical checks.
func (s *Sanitizer) isUnderSanitizedScope(inScope bool, key string, profile Profile) bool {
	return inScope || profile.ShouldSanitize(key)
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
			// Pass the current scope through so a map element
			// inside a sanitized list still has its scalars
			// redacted. The previous shape called ScrubMap, which
			// reset the scope to false at every map boundary.
			out[i] = s.scrubMapInScope(v, profile, inSanitizedScope)
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
	// Match the public-method nil-receiver pattern (ID, Asset,
	// Value, Path, Snapshot all fail-open on nil). The unexported
	// scrubAsset is only reached today via Snapshot, which already
	// guards, but a future caller plumbing a nil sanitiser through
	// must not panic mid-snapshot.
	if s == nil {
		return a
	}
	return asset.Asset{
		ID:         asset.ID(s.ID(string(a.ID))),
		Type:       a.Type,
		Vendor:     a.Vendor,
		Source:     s.scrubSource(a.Source),
		Properties: s.ScrubMap(a.Properties, AssetProfile()),
	}
}

func (s *Sanitizer) scrubIdentity(id asset.CloudIdentity) asset.CloudIdentity {
	// Symmetric nil-receiver guard with scrubAsset.
	if s == nil {
		return id
	}
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
		// Booleans are returned UNCHANGED. Booleans are never
		// sensitive on their own — `enabled: true` does not leak a
		// secret the way a string identifier might — and the
		// previous "scrub to false" path silently flipped control
		// verdicts when sanitized output was re-ingested (a `true`
		// became `false` and a `block_public_acls` finding turned
		// passing). Schema typing also stays intact: bool fields
		// declared in out.v0.1.json keep their declared type
		// regardless of the SanitizeIDs flag.
		//
		// If a future use case needs to distinguish "redacted" from
		// "really false", set the parent map key to a Sanitize-
		// flagged path so the value is removed entirely (the
		// neutral-key recursion above redacts every primitive
		// child of a Sanitize parent).
		return val
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
		// "0.0" rather than "0" so a downstream schema validator
		// expecting a float type still accepts the redacted value.
		// json.Number("0") parses as integer-shaped; some validators
		// reject it where the schema declares "number" with a
		// fractional shape.
		return json.Number("0.0")
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
		// scrubValueWithProfile is only called from a Sanitize-flagged
		// parent (ScrubMap routes there) — every primitive child must
		// be redacted, even under a neutrally-named key, otherwise a
		// sensitive scalar reachable through `aws.tags.email` would
		// leak verbatim because "email" isn't itself in the profile's
		// Sanitize set. The earlier "preserve primitives as-is" path
		// dropped exactly that protection.
		out := make(map[string]any, len(val))
		for k, sub := range val {
			if profile.ShouldRemove(k) {
				continue
			}
			// Inside a Sanitize-flagged scope every value is scrubbed
			// regardless of whether the key itself is classified.
			// scrubValueWithProfile (this function) recursively
			// applies the same rule.
			out[k] = s.scrubValueWithProfile(sub, profile)
		}
		return out
	default:
		// Reached when a leaf value's Go type isn't covered by the
		// switch above. Numbers, booleans, time stamps, and JSON
		// raw messages have dedicated cases; arriving here means a
		// new type leaked into the activation map (a custom struct
		// from a producer, a typed alias, etc.).
		//
		// Return a TYPE-PRESERVING zero via reflection. Earlier this
		// branch returned the string "SANITIZED_UNKNOWN_TYPE", which
		// flipped the slot's JSON type and broke downstream type
		// assertions in consumers that expected the producer-declared
		// shape. Reflection is the only way to get the right zero
		// without enumerating every possible Go type. We still log
		// so the schema-drift surfaces during triage.
		slog.Warn("sanitize: unknown leaf type, returning type-preserving zero value",
			"go_type", fmt.Sprintf("%T", v))
		rv := reflect.ValueOf(v)
		if !rv.IsValid() {
			return nil
		}
		// Wrap reflect.Zero in recover: certain unexported / opaque
		// types (interface satisfied by an internal struct,
		// reflect-unexported channel types from foreign packages)
		// can panic during Type() / Zero() construction. The
		// scrubber must NEVER bring down the assessment pipeline
		// for an unscrubbable leaf — fall back to nil + a debug
		// log so the producer is visible without crashing the
		// command.
		return safeReflectZero(rv)
	}
}

// safeReflectZero returns a type-preserving zero value, or nil when
// reflection panics. A non-empty recover reason is logged so the
// schema-drift signal still reaches operators without crashing the
// scrubber.
func safeReflectZero(rv reflect.Value) (out any) {
	defer func() {
		if r := recover(); r != nil {
			slog.Debug("sanitize: reflect.Zero panicked on unsupported type; falling back to nil",
				"recover", fmt.Sprint(r),
				"kind", rv.Kind().String())
			out = nil
		}
	}()
	return reflect.Zero(rv.Type()).Interface()
}
