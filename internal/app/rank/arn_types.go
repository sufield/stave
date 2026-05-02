package rank

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// IdentityARN identifies a single IAM principal participating in the
// rank pipeline. Wrapped as a typed string so the ranking layer can't
// silently accept a ResourceARN where an IdentityARN was expected
// (the two carry the same JSON shape but represent semantically
// different things — the source vs the target of access).
type IdentityARN string

// ResourceARN identifies a resource reachable by some identity. Same
// motivation as IdentityARN: structurally identical to its sibling,
// semantically distinct, and a costly mix-up if you swap them.
type ResourceARN string

// String / IsEmpty / Validate / Parse / Marshal / Unmarshal pairs
// follow the same pattern as kernel.AccountID so callers experience
// these values as ordinary string-like ids.

// String returns the raw ARN.
func (a IdentityARN) String() string { return string(a) }

// IsEmpty reports whether the ARN is unset.
func (a IdentityARN) IsEmpty() bool { return a == "" }

// Validate enforces non-empty and the ARN scheme prefix. The deeper
// shape check (12-digit account ID, IAM trailer) belongs in the AWS
// provider adapter — at this layer all we promise is that the value
// looks like an ARN rather than a free-form string.
func (a IdentityARN) Validate() error {
	if a.IsEmpty() {
		return errors.New("identity ARN must not be empty")
	}
	if !strings.HasPrefix(string(a), "arn:") {
		return fmt.Errorf("invalid identity ARN %q: missing arn: scheme prefix", string(a))
	}
	return nil
}

// ParseIdentityARN returns a validated IdentityARN.
func ParseIdentityARN(raw string) (IdentityARN, error) {
	id := IdentityARN(raw)
	if err := id.Validate(); err != nil {
		return "", err
	}
	return id, nil
}

// MarshalJSON serializes as a JSON string so the wire format stays
// identical to the previous untyped representation.
func (a IdentityARN) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.String())
}

// UnmarshalJSON delegates to UnmarshalText.
func (a *IdentityARN) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	return a.UnmarshalText([]byte(s))
}

// MarshalText implements encoding.TextMarshaler.
func (a IdentityARN) MarshalText() ([]byte, error) {
	return []byte(a.String()), nil
}

// UnmarshalText delegates to ParseIdentityARN.
func (a *IdentityARN) UnmarshalText(text []byte) error {
	parsed, err := ParseIdentityARN(string(text))
	if err != nil {
		return err
	}
	*a = parsed
	return nil
}

// String returns the raw ARN.
func (a ResourceARN) String() string { return string(a) }

// IsEmpty reports whether the ARN is unset.
func (a ResourceARN) IsEmpty() bool { return a == "" }

// Validate enforces non-empty and the ARN scheme prefix.
func (a ResourceARN) Validate() error {
	if a.IsEmpty() {
		return errors.New("resource ARN must not be empty")
	}
	if !strings.HasPrefix(string(a), "arn:") {
		return fmt.Errorf("invalid resource ARN %q: missing arn: scheme prefix", string(a))
	}
	return nil
}

// ParseResourceARN returns a validated ResourceARN.
func ParseResourceARN(raw string) (ResourceARN, error) {
	a := ResourceARN(raw)
	if err := a.Validate(); err != nil {
		return "", err
	}
	return a, nil
}

// MarshalJSON serializes as a JSON string.
func (a ResourceARN) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.String())
}

// UnmarshalJSON delegates to UnmarshalText.
func (a *ResourceARN) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	return a.UnmarshalText([]byte(s))
}

// MarshalText implements encoding.TextMarshaler.
func (a ResourceARN) MarshalText() ([]byte, error) {
	return []byte(a.String()), nil
}

// UnmarshalText delegates to ParseResourceARN.
func (a *ResourceARN) UnmarshalText(text []byte) error {
	parsed, err := ParseResourceARN(string(text))
	if err != nil {
		return err
	}
	*a = parsed
	return nil
}
