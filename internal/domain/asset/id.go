package asset

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
)

// ID is a domain-safe identifier for assets (resources and identities).
type ID string

// String returns the raw identifier value.
func (id ID) String() string {
	return string(id)
}

// IsEmpty reports whether the identifier has no value.
func (id ID) IsEmpty() bool {
	return id == ""
}

// Sanitize returns a sanitized copy of the identifier. The tokenFunc parameter
// produces a deterministic short token from a string (e.g. crypto.ShortToken).
// ARN structure is preserved: "arn:aws:s3:::SANITIZED_<token>/path".
// Plain names become "SANITIZED_<token>".
func (id ID) Sanitize(tokenFunc func(string) string) ID {
	raw := string(id)
	if raw == "" {
		return id
	}

	if name, ok := strings.CutPrefix(raw, "arn:aws:s3:::"); ok {
		bucket, path := name, ""
		if idx := strings.IndexByte(name, '/'); idx >= 0 {
			bucket, path = name[:idx], name[idx:]
		}
		// Single three-operand concat: one allocation (path is "" when absent).
		return ID("arn:aws:s3:::SANITIZED_" + tokenFunc(bucket) + path)
	}

	return ID("SANITIZED_" + tokenFunc(raw))
}

// ParseID validates and returns a domain-safe ID.
func ParseID(raw string) (ID, error) {
	if err := validateID(raw); err != nil {
		return "", err
	}
	return ID(raw), nil
}

// UnmarshalJSON validates resource identifiers at ingest time.
func (id *ID) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	parsed, err := ParseID(raw)
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}

func validateID(raw string) error {
	for _, r := range raw {
		if unicode.IsControl(r) {
			return fmt.Errorf("resource id %q contains control characters", raw)
		}
	}

	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("resource id must not be empty")
	}
	if trimmed != raw {
		return fmt.Errorf("resource id %q must not have leading or trailing whitespace", raw)
	}
	return nil
}
