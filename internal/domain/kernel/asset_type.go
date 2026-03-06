package kernel

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// AssetType represents the type of an infrastructure asset (e.g., "aws_s3_bucket").
type AssetType string

var resourceTypePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]*$`)

const (
	// TypeS3Bucket represents an AWS S3 bucket.
	TypeS3Bucket AssetType = "aws_s3_bucket"
	// TypeStorageBucket represents a generic storage bucket.
	TypeStorageBucket AssetType = "storage_bucket"
	// TypeStorageContainer represents a storage container.
	TypeStorageContainer AssetType = "storage_container"
	// TypeUploadPolicy represents an upload policy.
	TypeUploadPolicy AssetType = "upload_policy"
	// TypeIAMRole represents an IAM role.
	TypeIAMRole AssetType = "iam_role"
	// TypeServiceAccount represents a service account.
	TypeServiceAccount AssetType = "service_account"
)

// String implements fmt.Stringer.
func (rt AssetType) String() string {
	if rt == "" {
		return "unknown"
	}
	return string(rt)
}

// Domain extracts the top-level resource family (for example: "aws_s3" from "aws_s3_bucket").
func (rt AssetType) Domain() string {
	parts := strings.Split(rt.String(), "_")
	if len(parts) < 2 {
		return "unknown"
	}
	return strings.Join(parts[:2], "_")
}

// NewAssetType normalizes a raw asset type into canonical lowercase form.
func NewAssetType(raw string) AssetType {
	return AssetType(strings.ToLower(strings.TrimSpace(raw)))
}

// Validate checks whether the resource type satisfies domain naming rules.
func (rt AssetType) Validate() error {
	if rt == "" {
		return fmt.Errorf("resource type must be non-empty")
	}
	if !resourceTypePattern.MatchString(rt.String()) {
		return fmt.Errorf("invalid resource type %q: use lowercase alphanumerics with _, ., or -", rt.String())
	}
	return nil
}

// ParseAssetType validates and normalizes an asset type value.
func ParseAssetType(s string) (AssetType, error) {
	t := NewAssetType(s)
	if err := t.Validate(); err != nil {
		return "", err
	}
	return t, nil
}

// MarshalJSON writes the resource type as its normalized string form.
func (rt AssetType) MarshalJSON() ([]byte, error) {
	return json.Marshal(rt.String())
}

// UnmarshalJSON parses and validates resource type values from JSON payloads.
func (rt *AssetType) UnmarshalJSON(b []byte) error {
	var raw string
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}

	parsed := NewAssetType(raw)
	if parsed == "" {
		// Allow empty values at generic JSON boundaries; strict checks happen
		// through ParseAssetType/Validate in domain ingestion paths.
		*rt = ""
		return nil
	}

	if err := parsed.Validate(); err != nil {
		return err
	}

	*rt = parsed
	return nil
}
