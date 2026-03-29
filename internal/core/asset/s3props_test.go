package asset

import (
	"encoding/json"
	"testing"
	"time"
)

func TestS3BlockPublicAccess_JSON(t *testing.T) {
	tests := []struct {
		name       string
		input      S3BlockPublicAccess
		wantAll    bool
		wantFields int // non-zero fields after round-trip
	}{
		{
			name:    "zero value",
			input:   S3BlockPublicAccess{},
			wantAll: false,
		},
		{
			name:    "partial — only block ACLs",
			input:   S3BlockPublicAccess{BlockPublicACLs: true},
			wantAll: false,
		},
		{
			name: "fully enabled",
			input: S3BlockPublicAccess{
				BlockPublicACLs:       true,
				IgnorePublicACLs:      true,
				BlockPublicPolicy:     true,
				RestrictPublicBuckets: true,
			},
			wantAll: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.input)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var got S3BlockPublicAccess
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got.AllEnabled() != tc.wantAll {
				t.Errorf("AllEnabled: got %v, want %v", got.AllEnabled(), tc.wantAll)
			}
			if got != tc.input {
				t.Errorf("round-trip mismatch: got %+v, want %+v", got, tc.input)
			}
		})
	}
}

func TestS3WebsiteConfig_JSON(t *testing.T) {
	tests := []struct {
		name  string
		input S3WebsiteConfig
	}{
		{
			name:  "zero value",
			input: S3WebsiteConfig{},
		},
		{
			name:  "enabled only",
			input: S3WebsiteConfig{Enabled: true},
		},
		{
			name: "fully populated",
			input: S3WebsiteConfig{
				Enabled:       true,
				IndexDocument: new("index.html"),
				ErrorDocument: new("error.html"),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.input)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var got S3WebsiteConfig
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got.Enabled != tc.input.Enabled {
				t.Errorf("Enabled: got %v, want %v", got.Enabled, tc.input.Enabled)
			}
		})
	}
}

func TestS3VPCEndpointPolicy_JSON(t *testing.T) {
	tests := []struct {
		name  string
		input S3VPCEndpointPolicy
	}{
		{
			name:  "zero value",
			input: S3VPCEndpointPolicy{},
		},
		{
			name:  "endpoint only",
			input: S3VPCEndpointPolicy{EndpointID: "vpce-1a2b3c4d"},
		},
		{
			name: "fully populated",
			input: S3VPCEndpointPolicy{
				EndpointID:      "vpce-1a2b3c4d",
				PolicyJSON:      new(`{"Version":"2012-10-17"}`),
				RestrictsAccess: true,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.input)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var got S3VPCEndpointPolicy
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got.EndpointID != tc.input.EndpointID {
				t.Errorf("EndpointID: got %q, want %q", got.EndpointID, tc.input.EndpointID)
			}
			if got.RestrictsAccess != tc.input.RestrictsAccess {
				t.Errorf("RestrictsAccess: got %v, want %v", got.RestrictsAccess, tc.input.RestrictsAccess)
			}
		})
	}
}

func TestS3BucketProperties_JSON(t *testing.T) {
	created := time.Date(2024, 3, 15, 10, 30, 0, 0, time.UTC)

	tests := []struct {
		name  string
		input S3BucketProperties
	}{
		{
			name:  "zero value",
			input: S3BucketProperties{},
		},
		{
			name: "name and creation date only",
			input: S3BucketProperties{
				BucketName: "my-bucket",
				CreatedAt:  &created,
			},
		},
		{
			name: "with tags",
			input: S3BucketProperties{
				BucketName: "tagged-bucket",
				Tags:       map[string]string{"env": "prod", "team": "security"},
			},
		},
		{
			name: "fully populated",
			input: S3BucketProperties{
				BucketName: "full-bucket",
				CreatedAt:  &created,
				Tags:       map[string]string{"env": "prod"},
				BlockPublicAccess: &S3BlockPublicAccess{
					BlockPublicACLs:       true,
					IgnorePublicACLs:      true,
					BlockPublicPolicy:     true,
					RestrictPublicBuckets: true,
				},
				Website: &S3WebsiteConfig{
					Enabled:       true,
					IndexDocument: new("index.html"),
				},
				VPCEndpointPolicy: &S3VPCEndpointPolicy{
					EndpointID:      "vpce-abc123",
					RestrictsAccess: true,
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.input)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var got S3BucketProperties
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got.BucketName != tc.input.BucketName {
				t.Errorf("BucketName: got %q, want %q", got.BucketName, tc.input.BucketName)
			}
			if (got.CreatedAt == nil) != (tc.input.CreatedAt == nil) {
				t.Errorf("CreatedAt nil mismatch: got %v, want %v", got.CreatedAt, tc.input.CreatedAt)
			}
			if got.CreatedAt != nil && !got.CreatedAt.Equal(*tc.input.CreatedAt) {
				t.Errorf("CreatedAt: got %v, want %v", got.CreatedAt, tc.input.CreatedAt)
			}
			if (got.BlockPublicAccess == nil) != (tc.input.BlockPublicAccess == nil) {
				t.Errorf("BlockPublicAccess nil mismatch")
			}
			if (got.Website == nil) != (tc.input.Website == nil) {
				t.Errorf("Website nil mismatch")
			}
			if (got.VPCEndpointPolicy == nil) != (tc.input.VPCEndpointPolicy == nil) {
				t.Errorf("VPCEndpointPolicy nil mismatch")
			}
		})
	}
}
