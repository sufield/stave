package consolidate

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// AccountID is the application-layer identifier for one account in
// the consolidation report. Distinct from kernel.AccountID so the
// consolidation manifest can use a YAML-friendly type with its own
// validation gate without dragging in kernel-level invariants the
// manifest doesn't need.
//
// Why a separate type at this layer: a consolidation manifest is a
// user-authored YAML file, and ClusterID and AccountID are easy to
// confuse there. Distinct types prevent silent swaps at unmarshal
// time even when the underlying string shapes overlap.
type AccountID string

// ClusterID identifies a logical cluster in the consolidation
// hierarchy (e.g. an org-unit, environment grouping, or k8s cluster
// when the consolidation pivots on workload instead of account).
// Sibling type to AccountID for the same swap-prevention reason.
type ClusterID string

var consolidateIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// String returns the raw ID.
func (a AccountID) String() string { return string(a) }

// IsEmpty reports whether the ID is unset.
func (a AccountID) IsEmpty() bool { return a == "" }

// Validate enforces non-empty and the standard alphanumeric +
// separator shape used by every major cloud's account / project /
// subscription identifiers.
func (a AccountID) Validate() error {
	if a.IsEmpty() {
		return errors.New("account ID must not be empty")
	}
	if !consolidateIDPattern.MatchString(string(a)) {
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

// UnmarshalText delegates to ParseAccountID so JSON / YAML / text
// inputs share one validation path.
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

// MarshalJSON serializes as a JSON string.
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

// UnmarshalYAML lets gopkg.in/yaml.v3 round-trip account IDs through
// the same validation as JSON. Required so a typo in a manifest
// (e.g. accidentally pasting a cluster ID into an account_id field
// that fails the alphanumeric check) is rejected at load time.
func (a *AccountID) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	return a.UnmarshalText([]byte(s))
}

// String returns the raw ID.
func (c ClusterID) String() string { return string(c) }

// IsEmpty reports whether the ID is unset.
func (c ClusterID) IsEmpty() bool { return c == "" }

// Validate enforces non-empty and the standard alphanumeric +
// separator shape.
func (c ClusterID) Validate() error {
	if c.IsEmpty() {
		return errors.New("cluster ID must not be empty")
	}
	if !consolidateIDPattern.MatchString(string(c)) {
		return fmt.Errorf("invalid cluster ID %q: must be alphanumeric (with -, _, .)", string(c))
	}
	return nil
}

// ParseClusterID returns a validated ClusterID.
func ParseClusterID(raw string) (ClusterID, error) {
	id := ClusterID(raw)
	if err := id.Validate(); err != nil {
		return "", err
	}
	return id, nil
}

// UnmarshalText delegates to ParseClusterID.
func (c *ClusterID) UnmarshalText(text []byte) error {
	parsed, err := ParseClusterID(string(text))
	if err != nil {
		return err
	}
	*c = parsed
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (c ClusterID) MarshalText() ([]byte, error) {
	return []byte(c.String()), nil
}

// MarshalJSON serializes as a JSON string.
func (c ClusterID) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.String())
}

// UnmarshalJSON delegates to UnmarshalText.
func (c *ClusterID) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	return c.UnmarshalText([]byte(s))
}

// UnmarshalYAML lets a YAML cluster_id round-trip through the same
// validation as JSON.
func (c *ClusterID) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	return c.UnmarshalText([]byte(s))
}
