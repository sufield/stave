package app_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/sufield/stave/internal/domain/kernel"

	"github.com/sufield/stave/internal/domain/asset"

	output "github.com/sufield/stave/internal/adapters/output"
	outjson "github.com/sufield/stave/internal/adapters/output/json"
	service "github.com/sufield/stave/internal/app/service"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/domain/policy"
	clockadp "github.com/sufield/stave/internal/domain/ports"
)

// TestEvaluateOutput_ByteIdentical runs the same evaluation twice and verifies
// that the JSON output is byte-identical. This catches nondeterminism in key
// ordering, map iteration, or formatting.
func TestEvaluateOutput_ByteIdentical(t *testing.T) {
	baseTime := time.Date(2026, 1, 14, 0, 0, 0, 0, time.UTC)
	laterTime := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)

	snapshots := []asset.Snapshot{
		{
			SchemaVersion: "obs.v0.1",
			CapturedAt:    baseTime,
			Assets: []asset.Asset{
				{
					ID:     "my-bucket",
					Type:   kernel.TypeStorageBucket,
					Vendor: kernel.VendorAWS,
					Properties: map[string]any{
						"storage": map[string]any{
							"visibility": map[string]any{
								"public_read": true,
							},
						},
					},
				},
				{
					ID:     "safe-bucket",
					Type:   kernel.TypeStorageBucket,
					Vendor: kernel.VendorAWS,
					Properties: map[string]any{
						"storage": map[string]any{
							"visibility": map[string]any{
								"public_read": false,
							},
						},
					},
				},
			},
		},
		{
			SchemaVersion: "obs.v0.1",
			CapturedAt:    laterTime,
			Assets: []asset.Asset{
				{
					ID:     "my-bucket",
					Type:   kernel.TypeStorageBucket,
					Vendor: kernel.VendorAWS,
					Properties: map[string]any{
						"storage": map[string]any{
							"visibility": map[string]any{
								"public_read": true,
							},
						},
					},
				},
				{
					ID:     "safe-bucket",
					Type:   kernel.TypeStorageBucket,
					Vendor: kernel.VendorAWS,
					Properties: map[string]any{
						"storage": map[string]any{
							"visibility": map[string]any{
								"public_read": false,
							},
						},
					},
				},
			},
		},
	}

	ctl := policy.ControlDefinition{
		DSLVersion:  "ctrl.v1",
		ID:          "CTL.S3.PUBLIC.001",
		Name:        "S3 Public Read Access",
		Description: "Detects S3 buckets with public read enabled",
		Type:        policy.TypeUnsafeDuration,
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{
				{Field: "properties.storage.visibility.public_read", Op: "eq", Value: true},
			},
		},
	}
	_ = ctl.Prepare()
	controls := []policy.ControlDefinition{ctl}

	clock := clockadp.FixedClock{Time: laterTime}
	maxUnsafe := 0 * time.Hour
	enricher := remediation.NewMapper()

	// Run evaluation and serialize to JSON — twice
	var outputs [2][]byte
	for i := range 2 {
		result := service.Evaluate(service.EvaluateInput{
			Controls:  controls,
			Snapshots: snapshots,
			MaxUnsafe: maxUnsafe,
			Clock:     clock,
		})
		result.Run.ToolVersion = "test-v1"
		result.Run.InputHashes = &evaluation.InputHashes{
			Overall: "abc123",
			Files: map[evaluation.FilePath]kernel.Digest{
				"snap1.json": "hash1",
				"snap2.json": "hash2",
			},
		}

		writer := outjson.NewFindingWriter(true) // indent=true
		enriched := output.Enrich(enricher, nil, result)
		data, err := writer.MarshalFindings(enriched)
		if err != nil {
			t.Fatalf("run %d: MarshalFindings failed: %v", i, err)
		}
		var buf bytes.Buffer
		buf.Write(data)
		outputs[i] = buf.Bytes()
	}

	if !bytes.Equal(outputs[0], outputs[1]) {
		t.Errorf("apply output is NOT byte-identical across two runs:\n--- run 0 ---\n%s\n--- run 1 ---\n%s",
			outputs[0], outputs[1])
	}
}

// TestEvaluateOutput_ByteIdentical_MultipleControls tests determinism with
// multiple controls and assets to stress map iteration ordering.
func TestEvaluateOutput_ByteIdentical_MultipleControls(t *testing.T) {
	baseTime := time.Date(2026, 1, 14, 0, 0, 0, 0, time.UTC)
	laterTime := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)

	resources := []asset.Asset{
		{ID: "bucket-z", Type: kernel.TypeStorageBucket, Vendor: kernel.VendorAWS, Properties: map[string]any{
			"storage": map[string]any{"visibility": map[string]any{"public_read": true}},
		}},
		{ID: "bucket-a", Type: kernel.TypeStorageBucket, Vendor: kernel.VendorAWS, Properties: map[string]any{
			"storage": map[string]any{"visibility": map[string]any{"public_read": true}},
		}},
		{ID: "bucket-m", Type: kernel.TypeStorageBucket, Vendor: kernel.VendorAWS, Properties: map[string]any{
			"storage": map[string]any{"visibility": map[string]any{"public_read": false}},
		}},
	}

	snapshots := []asset.Snapshot{
		{SchemaVersion: "obs.v0.1", CapturedAt: baseTime, Assets: resources},
		{SchemaVersion: "obs.v0.1", CapturedAt: laterTime, Assets: resources},
	}

	ctlZ := policy.ControlDefinition{
		DSLVersion: "ctrl.v1", ID: "CTL.Z.001", Name: "Z control",
		Type: policy.TypeUnsafeDuration,
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{{Field: "properties.storage.visibility.public_read", Op: "eq", Value: true}},
		},
	}
	_ = ctlZ.Prepare()
	ctlA := policy.ControlDefinition{
		DSLVersion: "ctrl.v1", ID: "CTL.A.001", Name: "A control",
		Type: policy.TypeUnsafeDuration,
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{{Field: "properties.storage.visibility.public_read", Op: "eq", Value: true}},
		},
	}
	_ = ctlA.Prepare()
	controls := []policy.ControlDefinition{ctlZ, ctlA}

	clock := clockadp.FixedClock{Time: laterTime}
	maxUnsafe := 0 * time.Hour
	enricher := remediation.NewMapper()

	var outputs [10][]byte
	for i := range 10 {
		result := service.Evaluate(service.EvaluateInput{
			Controls:  controls,
			Snapshots: snapshots,
			MaxUnsafe: maxUnsafe,
			Clock:     clock,
		})
		result.Run.ToolVersion = "test-v1"

		writer := outjson.NewFindingWriter(true)
		enriched := output.Enrich(enricher, nil, result)
		data, err := writer.MarshalFindings(enriched)
		if err != nil {
			t.Fatalf("run %d: MarshalFindings failed: %v", i, err)
		}
		var buf bytes.Buffer
		buf.Write(data)
		outputs[i] = buf.Bytes()
	}

	for i := 1; i < 10; i++ {
		if !bytes.Equal(outputs[0], outputs[i]) {
			t.Errorf("output differs at run %d vs run 0:\n--- run 0 (first 500 bytes) ---\n%s\n--- run %d (first 500 bytes) ---\n%s",
				i, truncate(outputs[0], 500), i, truncate(outputs[i], 500))
		}
	}
}

func truncate(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[:n]
}
