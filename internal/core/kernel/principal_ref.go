package kernel

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// PrincipalRef identifies an IAM principal — a user, role, or
// service principal. Stored as a typed string with light scheme
// validation: must be a non-empty value carrying one of the
// recognised URI scheme prefixes (arn:, gcp:, azure:) or a
// service-principal hostname (anything ending in
// .amazonaws.com or .iam.gserviceaccount.com), so the kernel can
// reject obviously-wrong free-form strings without owning the full
// per-cloud principal grammar (that lives in the provider adapter).
type PrincipalRef string

// recognisedPrincipalSuffixes covers service-principal hostnames
// that legitimately appear as principals but don't carry an ARN
// scheme. AWS service principals like "lambda.amazonaws.com" and
// GCP service accounts ending in ".iam.gserviceaccount.com" are the
// known shapes; extend as needed when new clouds land.
var recognisedPrincipalSuffixes = []string{
	".amazonaws.com",
	".iam.gserviceaccount.com",
}

// String returns the raw ref string.
func (p PrincipalRef) String() string { return string(p) }

// IsEmpty reports whether the ref is unset.
func (p PrincipalRef) IsEmpty() bool { return p == "" }

// Validate enforces non-empty and a recognised prefix or suffix.
// The deeper shape rules (arn:aws:iam::<account>:user/<name> etc.)
// belong in the provider adapter — at this layer the contract is
// only "looks like an IAM principal".
func (p PrincipalRef) Validate() error {
	if p.IsEmpty() {
		return errors.New("principal ref must not be empty")
	}
	s := string(p)
	for _, scheme := range recognizedURISchemes {
		if strings.HasPrefix(s, scheme) {
			return nil
		}
	}
	for _, suffix := range recognisedPrincipalSuffixes {
		if strings.HasSuffix(s, suffix) {
			return nil
		}
	}
	return fmt.Errorf("invalid principal ref %q: must be an ARN-shaped URI or a known service-principal hostname", s)
}

// NewPrincipalRef returns a validated PrincipalRef.
func NewPrincipalRef(raw string) (PrincipalRef, error) {
	p := PrincipalRef(raw)
	if err := p.Validate(); err != nil {
		return "", err
	}
	return p, nil
}

// UnmarshalText delegates to NewPrincipalRef.
func (p *PrincipalRef) UnmarshalText(text []byte) error {
	parsed, err := NewPrincipalRef(string(text))
	if err != nil {
		return err
	}
	*p = parsed
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (p PrincipalRef) MarshalText() ([]byte, error) {
	return []byte(p.String()), nil
}

// MarshalJSON serialises as a JSON string.
func (p PrincipalRef) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.String())
}

// UnmarshalJSON delegates to UnmarshalText.
func (p *PrincipalRef) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	return p.UnmarshalText([]byte(s))
}
