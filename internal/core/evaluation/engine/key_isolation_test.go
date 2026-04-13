package engine

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
)

func TestParseSensitivity(t *testing.T) {
	tests := []struct {
		input string
		want  SensitivityLevel
	}{
		{"phi", SensitivityPHI},
		{"cde", SensitivityPHI},
		{"confidential", SensitivityConfidential},
		{"internal", SensitivityInternal},
		{"public", SensitivityPublic},
		{"non-sensitive", SensitivityPublic},
		{"", SensitivityUnclassified},
		{"unknown", SensitivityUnclassified},
		{"unclassified", SensitivityUnclassified},
	}
	for _, tt := range tests {
		if got := ParseSensitivity(tt.input); got != tt.want {
			t.Errorf("ParseSensitivity(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestBuildKeyUsageIndex_ExclusiveKey(t *testing.T) {
	snapshots := []asset.Snapshot{{
		Assets: []asset.Asset{
			makeKMSAsset("bucket-1", "arn:aws:kms:key-A", "phi"),
			makeKMSAsset("bucket-2", "arn:aws:kms:key-A", "phi"),
		},
	}}
	idx := BuildKeyUsageIndex(snapshots)
	entry := idx["arn:aws:kms:key-A"]
	if entry == nil {
		t.Fatal("expected entry for key-A")
	}
	if !entry.IsExclusive() {
		t.Fatal("key-A should be exclusive (both resources are phi)")
	}
}

func TestBuildKeyUsageIndex_SharedKey(t *testing.T) {
	snapshots := []asset.Snapshot{{
		Assets: []asset.Asset{
			makeKMSAsset("prod-db", "arn:aws:kms:key-B", "phi"),
			makeKMSAsset("dev-bucket", "arn:aws:kms:key-B", "dev"),
		},
	}}
	idx := BuildKeyUsageIndex(snapshots)
	entry := idx["arn:aws:kms:key-B"]
	if entry == nil {
		t.Fatal("expected entry for key-B")
	}
	if entry.IsExclusive() {
		t.Fatal("key-B should NOT be exclusive (phi + dev)")
	}
	if len(entry.Domains) != 2 {
		t.Fatalf("expected 2 domains, got %d", len(entry.Domains))
	}
}

func TestBuildKeyUsageIndex_NoKeyID(t *testing.T) {
	snapshots := []asset.Snapshot{{
		Assets: []asset.Asset{
			{ID: "bucket-no-key", Properties: map[string]any{
				"storage": map[string]any{"encryption": map[string]any{"at_rest_enabled": true}},
			}},
		},
	}}
	idx := BuildKeyUsageIndex(snapshots)
	if len(idx) != 0 {
		t.Fatalf("expected empty index for assets without kms_key_id, got %d entries", len(idx))
	}
}

func TestBuildKeyUsageIndex_EmptySnapshots(t *testing.T) {
	idx := BuildKeyUsageIndex(nil)
	if idx != nil {
		t.Fatal("expected nil index for empty snapshots")
	}
}

func TestBuildKeyUsageIndex_MissingClassification(t *testing.T) {
	snapshots := []asset.Snapshot{{
		Assets: []asset.Asset{
			{ID: "bucket-no-tag", Properties: map[string]any{
				"cryptography": map[string]any{"kms_key_id": "arn:aws:kms:key-C"},
			}},
		},
	}}
	idx := BuildKeyUsageIndex(snapshots)
	entry := idx["arn:aws:kms:key-C"]
	if entry == nil {
		t.Fatal("expected entry for key-C")
	}
	if _, ok := entry.Domains["unclassified"]; !ok {
		t.Fatal("missing classification should default to 'unclassified'")
	}
}

func TestEnrichKeyIsolation_SetsProperty(t *testing.T) {
	snapshots := []asset.Snapshot{{
		Assets: []asset.Asset{
			makeKMSAsset("prod-db", "arn:aws:kms:key-D", "phi"),
			makeKMSAsset("dev-bucket", "arn:aws:kms:key-D", "dev"),
		},
	}}
	idx := BuildKeyUsageIndex(snapshots)
	enriched := EnrichKeyIsolation(snapshots, idx)

	a := enriched[0].Assets[0]
	crypto, ok := a.Properties["cryptography"].(map[string]any)
	if !ok {
		t.Fatal("expected cryptography property")
	}
	isolation, ok := crypto["key_isolation"].(map[string]any)
	if !ok {
		t.Fatal("expected key_isolation sub-object")
	}
	if exclusive, ok := isolation["is_exclusive_to_domain"].(bool); !ok || exclusive {
		t.Fatal("is_exclusive_to_domain should be false for shared key")
	}
	if mixed, ok := isolation["mixed_classification"].(bool); !ok || !mixed {
		t.Fatal("mixed_classification should be true for shared key")
	}
}

func TestEnrichKeyIsolation_DoesNotMutateOriginal(t *testing.T) {
	original := []asset.Snapshot{{
		Assets: []asset.Asset{
			makeKMSAsset("prod-db", "arn:aws:kms:key-E", "phi"),
			makeKMSAsset("dev-bucket", "arn:aws:kms:key-E", "dev"),
		},
	}}
	idx := BuildKeyUsageIndex(original)
	_ = EnrichKeyIsolation(original, idx)

	// Original should not have key_isolation.
	crypto, ok := original[0].Assets[0].Properties["cryptography"].(map[string]any)
	if !ok {
		t.Fatal("expected cryptography property on original")
	}
	if _, exists := crypto["key_isolation"]; exists {
		t.Fatal("EnrichKeyIsolation should not mutate the original snapshot")
	}
}

func TestEnrichKeyIsolation_NilIndex(t *testing.T) {
	snapshots := []asset.Snapshot{{
		Assets: []asset.Asset{makeKMSAsset("bucket", "key", "phi")},
	}}
	result := EnrichKeyIsolation(snapshots, nil)
	if len(result) != 1 || len(result[0].Assets) != 1 {
		t.Fatal("nil index should return snapshots unchanged")
	}
}

func TestKeyUsageEntry_IsExclusive_SingleDomain(t *testing.T) {
	entry := &KeyUsageEntry{MinLevel: SensitivityPHI, MaxLevel: SensitivityPHI}
	if !entry.IsExclusive() {
		t.Fatal("single domain should be exclusive")
	}
}

func TestKeyUsageEntry_IsExclusive_MultipleDomains(t *testing.T) {
	entry := &KeyUsageEntry{MinLevel: SensitivityPublic, MaxLevel: SensitivityPHI}
	if entry.IsExclusive() {
		t.Fatal("multiple domains should not be exclusive")
	}
}

func makeKMSAsset(id, keyARN, classification string) asset.Asset {
	return asset.Asset{
		ID:   asset.ID(id),
		Type: "aws_s3_bucket",
		Properties: map[string]any{
			"cryptography": map[string]any{
				"kms_key_id": keyARN,
			},
			"tags": map[string]any{
				"data-classification": classification,
			},
		},
	}
}
