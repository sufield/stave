package domain

import (
	"testing"

	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"

	"github.com/sufield/stave/internal/domain/asset"
)

// writeScopePredicate returns a generic "write scope must be exact key" predicate.
func writeScopePredicate() policy.UnsafePredicate {
	return policy.UnsafePredicate{
		All: []policy.PredicateRule{
			{Field: "type", Op: "eq", Value: "upload_policy"},
			{Field: "properties.upload.operation", Op: "eq", Value: "write"},
			{Field: "properties.upload.allowed_key_mode", Op: "eq", Value: "prefix"},
		},
	}
}

func uploadPolicyResource(keyMode string) asset.Asset {
	return asset.Asset{
		ID:     "upload-policy-test",
		Type:   kernel.AssetType("upload_policy"),
		Vendor: kernel.Vendor("aws"),
		Properties: map[string]any{
			"upload": map[string]any{
				"container":        "test-container",
				"operation":        "write",
				"allowed_key_mode": keyMode,
			},
		},
	}
}

func TestWriteScope_PrefixModeIsUnsafe(t *testing.T) {
	pred := writeScopePredicate()
	r := uploadPolicyResource("prefix")
	if !pred.Evaluate(r, nil) {
		t.Error("expected prefix-mode upload policy to be unsafe")
	}
}

func TestWriteScope_ExactModeIsSafe(t *testing.T) {
	pred := writeScopePredicate()
	r := uploadPolicyResource("exact")
	if pred.Evaluate(r, nil) {
		t.Error("expected exact-mode upload policy to be safe")
	}
}

func TestWriteScope_DifferentResourceTypeDoesNotMatch(t *testing.T) {
	pred := writeScopePredicate()
	r := asset.Asset{
		ID:     "some-container",
		Type:   kernel.AssetType("storage_container"),
		Vendor: kernel.Vendor("aws"),
		Properties: map[string]any{
			"storage": map[string]any{
				"access": map[string]any{
					"public_read": true,
				},
			},
		},
	}
	if pred.Evaluate(r, nil) {
		t.Error("expected non-upload-policy resource to not match")
	}
}

func TestWriteScope_ReadOperationDoesNotMatch(t *testing.T) {
	pred := writeScopePredicate()
	r := asset.Asset{
		ID:     "upload-policy-read",
		Type:   kernel.AssetType("upload_policy"),
		Vendor: kernel.Vendor("aws"),
		Properties: map[string]any{
			"upload": map[string]any{
				"container":        "test-container",
				"operation":        "read",
				"allowed_key_mode": "prefix",
			},
		},
	}
	if pred.Evaluate(r, nil) {
		t.Error("expected read operation to not match write-scope control")
	}
}

func TestWriteScope_MissingFieldsDoNotMatch(t *testing.T) {
	pred := writeScopePredicate()

	tests := []struct {
		name  string
		props map[string]any
	}{
		{
			"missing allowed_key_mode",
			map[string]any{
				"upload": map[string]any{
					"operation": "write",
				},
			},
		},
		{
			"empty properties",
			map[string]any{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := asset.Asset{
				ID:         "test",
				Type:       kernel.AssetType("upload_policy"),
				Vendor:     kernel.Vendor("aws"),
				Properties: tt.props,
			}
			if pred.Evaluate(r, nil) {
				t.Error("expected missing fields to not match")
			}
		})
	}
}
