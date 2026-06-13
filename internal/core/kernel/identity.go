package kernel

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// Identity type aliases for domain concepts that are used as identifiers
// across the codebase. AccountID and ResourceURI carry boundary
// validation (non-empty + structural shape) so the core does not depend
// on any specific cloud's identifier format. Vendor-specific shapes
// (12-digit AWS account IDs, AWS ARN parsing) live behind a provider
// adapter — see internal/platform/providers/aws.

// AssetDomain identifies the domain segment of a control or asset type (e.g., "s3", "iam").
type AssetDomain string

// PackName is a typed string identifying a control pack
// (e.g., "s3/public", "hipaa", "cis-aws-v1").
type PackName string

// ScopeTag is a typed string identifying a scope or classification tag
// on a control definition (e.g., "aws", "s3", "compliance").
type ScopeTag string

// AccountID is a vendor-agnostic cloud account / project / subscription
// identifier. The kernel enforces only the bare minimum invariant
// (non-empty alphanumeric) so the same type can flow through AWS,
// GCP, and Azure code paths. Per-vendor shape rules (e.g. AWS's
// 12-digit constraint) live in the corresponding provider package.
type AccountID string

// accountIDPattern enforces only structural soundness — alphanumeric
// plus the small set of separators that legitimate account / project
// / subscription identifiers use across major clouds. Vendor-specific
// length / format checks belong in the provider adapter.
var accountIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// String returns the raw account ID.
func (a AccountID) String() string { return string(a) }

// IsEmpty reports whether the account ID is unset.
func (a AccountID) IsEmpty() bool { return a == "" }

// Validate enforces the kernel's vendor-agnostic invariants:
// non-empty, alphanumeric (with the standard separator characters).
// Vendor-specific shape checks (e.g. AWS's 12-digit rule) are the
// provider's responsibility.
func (a AccountID) Validate() error {
	if a.IsEmpty() {
		return errors.New("account ID must not be empty")
	}
	if !accountIDPattern.MatchString(string(a)) {
		return fmt.Errorf("invalid account ID %q: must be alphanumeric (with -, _, .)", string(a))
	}
	return nil
}

// ParseAccountID returns a validated AccountID.
func ParseAccountID(raw string) (AccountID, error) {
	id := AccountID(raw)
	if err := id.Validate(); err != nil {
		return "", err
	}
	return id, nil
}

// UnmarshalText implements encoding.TextUnmarshaler so JSON / YAML
// inputs share a single validation gate.
func (a *AccountID) UnmarshalText(text []byte) error {
	parsed, err := ParseAccountID(string(text))
	if err != nil {
		return err
	}
	*a = parsed
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (a AccountID) MarshalText() ([]byte, error) {
	return []byte(a.String()), nil
}

// MarshalJSON serializes the account ID as a JSON string.
func (a AccountID) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.String())
}

// UnmarshalJSON delegates to UnmarshalText.
func (a *AccountID) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	return a.UnmarshalText([]byte(s))
}

// ResourceURI is a vendor-agnostic resource identifier. The kernel
// requires only that the value carry a recognized scheme prefix —
// arn: (AWS), gcp:, or azure:. Schema-level interpretation (parsing
// an ARN into account/service/resource) lives in the provider adapter
// (internal/platform/providers/aws, etc.). The core treats the value
// as an opaque URI.
type ResourceURI string

// recognizedURISchemes are the scheme prefixes that ResourceURI
// accepts at the kernel boundary. Provider packages register their
// scheme via RegisterURIScheme at init time; kernel ships with the
// historical AWS / GCP / Azure defaults as a transitional seed so
// existing consumers continue to validate without an explicit
// provider registration. Phase 5 of the provider-extraction plan
// will drop the seed once the AWS provider's init() takes over.
// uriSchemeRegistry is the concurrency-safe set of scheme prefixes that
// ResourceURI accepts at the kernel boundary. Bundling the slice with the
// RWMutex that guards it keeps the lock and data in one type. The kernel seeds
// the historical arn:/gcp:/azure: defaults; providers add their scheme via
// RegisterURIScheme from their Register() entrypoint.
type uriSchemeRegistry struct {
	mu      sync.RWMutex
	schemes []string
}

// register adds scheme to the set. Idempotent; empty input is ignored.
func (r *uriSchemeRegistry) register(scheme string) {
	if scheme == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !slices.Contains(r.schemes, scheme) {
		r.schemes = append(r.schemes, scheme)
	}
}

// matches reports whether uri begins with any registered scheme.
func (r *uriSchemeRegistry) matches(uri string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, scheme := range r.schemes {
		if strings.HasPrefix(uri, scheme) {
			return true
		}
	}
	return false
}

// snapshot returns a copy of the current set for diagnostic messages.
func (r *uriSchemeRegistry) snapshot() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return slices.Clone(r.schemes)
}

// uriSchemes is the process-wide URI-scheme registry — one cohesive instance
// rather than a loose mutex+slice pair.
var uriSchemes = &uriSchemeRegistry{schemes: []string{"arn:", "gcp:", "azure:"}}

// RegisterURIScheme adds scheme to the set of prefixes ResourceURI
// accepts. Idempotent: registering the same scheme twice is a no-op.
// Call this from a provider package's Register() entrypoint so the
// scheme is available before any caller validates a URI carrying it.
func RegisterURIScheme(scheme string) {
	uriSchemes.register(scheme)
}

// IsRecognizedURIScheme reports whether uri begins with a registered
// scheme. Used by ResourceURI.Validate so callers stop reaching for
// the package-level slice directly.
func IsRecognizedURIScheme(uri string) bool {
	return uriSchemes.matches(uri)
}

// String returns the raw URI string.
func (u ResourceURI) String() string { return string(u) }

// IsEmpty reports whether the URI is unset.
func (u ResourceURI) IsEmpty() bool { return u == "" }

// Validate ensures the URI is non-empty and carries one of the
// registered scheme prefixes. The kernel does not interpret the
// scheme's body — that is the provider adapter's responsibility.
func (u ResourceURI) Validate() error {
	if u.IsEmpty() {
		return errors.New("resource URI must not be empty")
	}
	if IsRecognizedURIScheme(string(u)) {
		return nil
	}
	return fmt.Errorf("invalid resource URI %q: must start with one of %v", string(u), uriSchemes.snapshot())
}

// ParseResourceURI returns a validated ResourceURI.
func ParseResourceURI(raw string) (ResourceURI, error) {
	uri := ResourceURI(raw)
	if err := uri.Validate(); err != nil {
		return "", err
	}
	return uri, nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (u *ResourceURI) UnmarshalText(text []byte) error {
	parsed, err := ParseResourceURI(string(text))
	if err != nil {
		return err
	}
	*u = parsed
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (u ResourceURI) MarshalText() ([]byte, error) {
	return []byte(u.String()), nil
}

// MarshalJSON serializes the URI as a JSON string.
func (u ResourceURI) MarshalJSON() ([]byte, error) {
	return json.Marshal(u.String())
}

// UnmarshalJSON delegates to UnmarshalText.
func (u *ResourceURI) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	return u.UnmarshalText([]byte(s))
}

// ObservationSourceType identifies the extraction method that produced an observation.
type ObservationSourceType string

// observationSourceTypeRegistry is the concurrency-safe set of known
// observation source types. Bundling the slice with the RWMutex that guards it
// keeps the lock and data in one type; providers register via
// RegisterObservationSourceType from their Register() entrypoint.
type observationSourceTypeRegistry struct {
	mu    sync.RWMutex
	types []ObservationSourceType
}

// register adds t to the set. Idempotent; empty input is ignored.
func (r *observationSourceTypeRegistry) register(t ObservationSourceType) {
	if t.IsEmpty() {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !slices.Contains(r.types, t) {
		r.types = append(r.types, t)
	}
}

// snapshot returns a copy of the registered source types.
func (r *observationSourceTypeRegistry) snapshot() []ObservationSourceType {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return slices.Clone(r.types)
}

// observationSourceTypeReg is the process-wide source-type registry — one
// cohesive instance rather than a loose mutex+slice pair.
var observationSourceTypeReg = &observationSourceTypeRegistry{}

// RegisterObservationSourceType adds t to the kernel's known
// source-type registry. Idempotent: registering the same type twice
// is a no-op. Provider packages call this from their Register()
// entrypoint so the type is enumerable through
// KnownObservationSourceTypes without the kernel needing per-vendor
// constants.
func RegisterObservationSourceType(t ObservationSourceType) {
	observationSourceTypeReg.register(t)
}

// KnownObservationSourceTypes returns a copy of the registered
// source types. Used by the capabilities manifest so it doesn't
// need to enumerate vendor-specific types itself.
func KnownObservationSourceTypes() []ObservationSourceType {
	return observationSourceTypeReg.snapshot()
}

func (t ObservationSourceType) String() string { return string(t) }

// IsEmpty reports whether the source type is unset.
func (t ObservationSourceType) IsEmpty() bool { return t == "" }
