package asset

import (
	"encoding/json"
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

// ParseID validates and returns a domain-safe ID.
func ParseID(raw string) (ID, error) {
	if err := validateID(raw); err != nil {
		return "", err
	}
	return ID(raw), nil
}

// UnmarshalJSON validates asset identifiers at ingest time.
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
		return fmt.Errorf("asset id must not be empty")
	}
	if trimmed != raw {
		return fmt.Errorf("asset id %q must not have leading or trailing whitespace", raw)
	}
	return nil
}
