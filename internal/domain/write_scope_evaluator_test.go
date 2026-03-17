package domain

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"

	clockadp "github.com/sufield/stave/internal/domain/ports"
)

// TestEvaluator_WriteScope_PrefixModeViolation verifies full evaluation behavior
// for a generic upload policy that allows prefix-scoped writes.
func TestEvaluator_WriteScope_PrefixModeViolation(t *testing.T) {
	controls := []policy.ControlDefinition{
		{
			ID:          "CTL.UPLOAD.WRITE.SCOPE.001",
			Name:        "Signed Upload Must Bind To Exact Object Key",
			Type:        policy.TypeUnsafeState,
			Description: "Signed upload policies must restrict write permission to a single exact object key.",
			UnsafePredicate: policy.UnsafePredicate{
				All: []policy.PredicateRule{
					{Field: "type", Op: "eq", Value: policy.Str("upload_policy")},
					{Field: "properties.upload.operation", Op: "eq", Value: policy.Str("write")},
					{Field: "properties.upload.allowed_key_mode", Op: "eq", Value: policy.Str("prefix")},
				},
			},
		},
	}

	snapshots := []asset.Snapshot{
		{
			CapturedAt: mustParseTime("2026-01-01T00:00:00Z"),
			Assets: []asset.Asset{
				{
					ID:     "orders-storage",
					Type:   kernel.AssetType("storage_container"),
					Vendor: kernel.Vendor("aws"),
					Properties: map[string]any{
						"storage": map[string]any{
							"kind": "container",
							"name": "orders-storage",
						},
					},
				},
				{
					ID:     "upload-policy-prefix",
					Type:   kernel.AssetType("upload_policy"),
					Vendor: kernel.Vendor("aws"),
					Properties: map[string]any{
						"upload": map[string]any{
							"container":        "orders-storage",
							"operation":        "write",
							"allowed_key_mode": "prefix",
							"allowed_prefix":   "files/",
						},
					},
				},
			},
		},
		{
			CapturedAt: mustParseTime("2026-01-11T00:00:00Z"),
			Assets: []asset.Asset{
				{
					ID:     "orders-storage",
					Type:   kernel.AssetType("storage_container"),
					Vendor: kernel.Vendor("aws"),
					Properties: map[string]any{
						"storage": map[string]any{
							"kind": "container",
							"name": "orders-storage",
						},
					},
				},
				{
					ID:     "upload-policy-prefix",
					Type:   kernel.AssetType("upload_policy"),
					Vendor: kernel.Vendor("aws"),
					Properties: map[string]any{
						"upload": map[string]any{
							"container":        "orders-storage",
							"operation":        "write",
							"allowed_key_mode": "prefix",
							"allowed_prefix":   "files/",
						},
					},
				},
			},
		},
	}

	maxUnsafe := 168 * time.Hour
	clock := clockadp.FixedClock(mustParseTime("2026-01-11T00:00:00Z"))

	evaluator := NewEvaluator(controls, maxUnsafe, clock)
	result := evaluator.Evaluate(snapshots)

	if result.Summary.Violations != 1 {
		t.Errorf("Expected 1 violation, got %d", result.Summary.Violations)
	}
	if result.Summary.AttackSurface != 1 {
		t.Errorf("Expected 1 currently unsafe, got %d", result.Summary.AttackSurface)
	}
	if result.Summary.AssetsEvaluated != 2 {
		t.Errorf("Expected 2 resources evaluated, got %d", result.Summary.AssetsEvaluated)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("Expected 1 finding, got %d", len(result.Findings))
	}

	finding := result.Findings[0]
	if finding.ControlID != "CTL.UPLOAD.WRITE.SCOPE.001" {
		t.Errorf("Expected control CTL.UPLOAD.WRITE.SCOPE.001, got %s", finding.ControlID)
	}
	if finding.AssetID != "upload-policy-prefix" {
		t.Errorf("Expected resource upload-policy-prefix, got %s", finding.AssetID)
	}
	if finding.AssetType != "upload_policy" {
		t.Errorf("Expected resource type upload_policy, got %s", finding.AssetType)
	}
	if finding.Evidence.UnsafeDurationHours != 240 {
		t.Errorf("Expected 240h unsafe duration, got %f", finding.Evidence.UnsafeDurationHours)
	}
	if finding.Evidence.ThresholdHours != 168 {
		t.Errorf("Expected 168h threshold, got %f", finding.Evidence.ThresholdHours)
	}
}

func TestEvaluator_WriteScope_ExactModeNoViolation(t *testing.T) {
	controls := []policy.ControlDefinition{
		{
			ID:   "CTL.UPLOAD.WRITE.SCOPE.001",
			Name: "Signed Upload Must Bind To Exact Object Key",
			Type: policy.TypeUnsafeState,
			UnsafePredicate: policy.UnsafePredicate{
				All: []policy.PredicateRule{
					{Field: "type", Op: "eq", Value: policy.Str("upload_policy")},
					{Field: "properties.upload.operation", Op: "eq", Value: policy.Str("write")},
					{Field: "properties.upload.allowed_key_mode", Op: "eq", Value: policy.Str("prefix")},
				},
			},
		},
	}

	snapshots := []asset.Snapshot{
		{
			CapturedAt: mustParseTime("2026-01-01T00:00:00Z"),
			Assets: []asset.Asset{
				{
					ID:     "upload-policy-exact",
					Type:   kernel.AssetType("upload_policy"),
					Vendor: kernel.Vendor("aws"),
					Properties: map[string]any{
						"upload": map[string]any{
							"container":        "orders-storage",
							"operation":        "write",
							"allowed_key_mode": "exact",
							"key_exact":        "uploads/abc123.jpg",
						},
					},
				},
			},
		},
		{
			CapturedAt: mustParseTime("2026-01-11T00:00:00Z"),
			Assets: []asset.Asset{
				{
					ID:     "upload-policy-exact",
					Type:   kernel.AssetType("upload_policy"),
					Vendor: kernel.Vendor("aws"),
					Properties: map[string]any{
						"upload": map[string]any{
							"container":        "orders-storage",
							"operation":        "write",
							"allowed_key_mode": "exact",
							"key_exact":        "uploads/abc123.jpg",
						},
					},
				},
			},
		},
	}

	maxUnsafe := 168 * time.Hour
	clock := clockadp.FixedClock(mustParseTime("2026-01-11T00:00:00Z"))

	evaluator := NewEvaluator(controls, maxUnsafe, clock)
	result := evaluator.Evaluate(snapshots)

	if result.Summary.Violations != 0 {
		t.Errorf("Expected 0 violations for exact key mode, got %d", result.Summary.Violations)
	}
	if result.Summary.AttackSurface != 0 {
		t.Errorf("Expected 0 currently unsafe for exact key mode, got %d", result.Summary.AttackSurface)
	}
}

func TestEvaluator_WriteScope_NoUploadPolicyObservations(t *testing.T) {
	controls := []policy.ControlDefinition{
		{
			ID:   "CTL.UPLOAD.WRITE.SCOPE.001",
			Name: "Signed Upload Must Bind To Exact Object Key",
			Type: policy.TypeUnsafeState,
			UnsafePredicate: policy.UnsafePredicate{
				All: []policy.PredicateRule{
					{Field: "type", Op: "eq", Value: policy.Str("upload_policy")},
					{Field: "properties.upload.operation", Op: "eq", Value: policy.Str("write")},
					{Field: "properties.upload.allowed_key_mode", Op: "eq", Value: policy.Str("prefix")},
				},
			},
		},
	}

	snapshots := []asset.Snapshot{
		{
			CapturedAt: mustParseTime("2026-01-01T00:00:00Z"),
			Assets: []asset.Asset{
				{
					ID:     "orders-storage",
					Type:   kernel.AssetType("storage_container"),
					Vendor: kernel.Vendor("aws"),
					Properties: map[string]any{
						"storage": map[string]any{
							"access": map[string]any{
								"public_read": true,
							},
						},
					},
				},
			},
		},
		{
			CapturedAt: mustParseTime("2026-01-11T00:00:00Z"),
			Assets: []asset.Asset{
				{
					ID:     "orders-storage",
					Type:   kernel.AssetType("storage_container"),
					Vendor: kernel.Vendor("aws"),
					Properties: map[string]any{
						"storage": map[string]any{
							"access": map[string]any{
								"public_read": true,
							},
						},
					},
				},
			},
		},
	}

	maxUnsafe := 168 * time.Hour
	clock := clockadp.FixedClock(mustParseTime("2026-01-11T00:00:00Z"))

	evaluator := NewEvaluator(controls, maxUnsafe, clock)
	result := evaluator.Evaluate(snapshots)

	if result.Summary.Violations != 0 {
		t.Errorf("Expected 0 violations when no upload policy observations exist, got %d", result.Summary.Violations)
	}
}
