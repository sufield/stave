package asset

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// ID is a domain-safe identifier for assets (assets and identities).
type ID string

// String returns the raw identifier value.
func (id ID) String() string {
	return string(id)
}

// IsEmpty reports whether the identifier has no value.
func (id ID) IsEmpty() bool {
	return id == ""
}

// IsARN reports whether this asset ID is shaped like an AWS ARN
// (i.e. starts with "arn:aws:"). Replaces the inline
// strings.HasPrefix probe in adapters/output/dto so the ARN
// detection rule lives on the type that owns the identifier.
func (id ID) IsARN() bool {
	return strings.HasPrefix(string(id), "arn:aws:")
}

// Region returns the region component of an AWS ARN, or "" when the
// ID is not an ARN or the format does not include a region segment.
// AWS ARNs follow arn:aws:<service>:<region>:<account>:<resource>
// — the region is the fourth colon-separated field. Non-ARN IDs and
// truncated ARNs return "" so callers can ignore a missing region
// without re-parsing.
func (id ID) Region() string {
	if !id.IsARN() {
		return ""
	}
	parts := strings.SplitN(string(id), ":", 6)
	if len(parts) < 6 {
		return ""
	}
	return parts[3]
}

// ParseID validates and returns a domain-safe ID.
func ParseID(raw string) (ID, error) {
	if err := validateID(raw); err != nil {
		return "", err
	}
	return ID(raw), nil
}

// UnmarshalJSON validates asset identifiers during JSON deserialization.
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
			return fmt.Errorf("asset id %q contains control characters", raw)
		}
	}

	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return errors.New("asset id must not be empty")
	}
	if trimmed != raw {
		return fmt.Errorf("asset id %q must not have leading or trailing whitespace", raw)
	}
	return nil
}
