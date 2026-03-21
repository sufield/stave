package kernel

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// AssetType represents a normalized identifier for an infrastructure resource type.
// Example: "aws_s3_bucket" or "gcp_compute_instance".
type AssetType string

// assetTypePattern enforces lowercase alphanumeric names with limited separators.
var assetTypePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]*$`)

const (
	// UnknownAsset represents a missing or unidentifiable asset type.
	UnknownAsset AssetType = "unknown"
)

// NewAssetType creates a normalized AssetType from a raw string.
func NewAssetType(raw string) AssetType {
	return AssetType(strings.ToLower(strings.TrimSpace(raw)))
}

// String returns the string representation.
func (a AssetType) String() string {
	if a == "" {
		return string(UnknownAsset)
	}
	return string(a)
}

// Domain extracts the provider/family prefix.
// For "aws_s3_bucket", it returns "aws_s3".
// For "storage_bucket", it returns "storage".
func (a AssetType) Domain() string {
	s := a.String()
	parts := strings.Split(s, "_")
	if len(parts) < 2 {
		return parts[0]
	}
	// Convention: the domain is the first two segments if they exist.
	return strings.Join(parts[:2], "_")
}

// Validate ensures the AssetType adheres to the system's naming constraints.
func (a AssetType) Validate() error {
	s := string(a)
	if s == "" || a == UnknownAsset {
		return fmt.Errorf("asset type is required")
	}
	if !assetTypePattern.MatchString(s) {
		return fmt.Errorf("invalid asset type %q: must be lowercase alphanumerics with underscores, dots, or hyphens", s)
	}
	return nil
}

// MarshalJSON ensures the type is always serialized in its canonical string form.
func (a AssetType) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.String())
}

// UnmarshalJSON validates the asset type during deserialization to prevent
// invalid data from entering the domain model.
func (a *AssetType) UnmarshalJSON(b []byte) error {
	var raw string
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}

	normalized := NewAssetType(raw)
	if normalized == "" || normalized == UnknownAsset {
		*a = ""
		return nil
	}

	if err := normalized.Validate(); err != nil {
		return err
	}

	*a = normalized
	return nil
}
