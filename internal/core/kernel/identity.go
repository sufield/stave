package kernel

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
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
// accepts at the kernel boundary. Add a new vendor by appending its
// scheme here and wiring the provider adapter alongside.
var recognizedURISchemes = []string{"arn:", "gcp:", "azure:"}

// String returns the raw URI string.
func (u ResourceURI) String() string { return string(u) }

// IsEmpty reports whether the URI is unset.
func (u ResourceURI) IsEmpty() bool { return u == "" }

// Validate ensures the URI is non-empty and carries one of the
// recognized scheme prefixes. The kernel does not interpret the
// scheme's body — that is the provider adapter's responsibility.
func (u ResourceURI) Validate() error {
	if u.IsEmpty() {
		return errors.New("resource URI must not be empty")
	}
	for _, scheme := range recognizedURISchemes {
		if strings.HasPrefix(string(u), scheme) {
			return nil
		}
	}
	return fmt.Errorf("invalid resource URI %q: must start with one of %v", string(u), recognizedURISchemes)
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

// SourceTypeAWSS3Snapshot is the canonical source type for AWS S3 snapshot observations.
const SourceTypeAWSS3Snapshot ObservationSourceType = "aws-s3-snapshot"

func (t ObservationSourceType) String() string { return string(t) }

// IsEmpty reports whether the source type is unset.
func (t ObservationSourceType) IsEmpty() bool { return t == "" }
