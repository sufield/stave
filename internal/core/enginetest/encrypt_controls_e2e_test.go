package enginetest

// E2E tests for S3 Encryption controls (ENCRYPT.001-004).
// Tests the full pipeline: observation fixture → built-in control YAML
// → predicate evaluation → CEL engine → findings.
//
// Test matrix:
//   - ENCRYPT.001: at_rest_enabled=false → violation (gated by kind=bucket)
//   - ENCRYPT.002: in_transit_enforced=false → violation (gated by kind=bucket)
//   - ENCRYPT.003: PHI bucket not using SSE-KMS with CMK → violation (gated by tag)
//   - ENCRYPT.004: classified data using AES256 instead of KMS → violation (gated by tag+kind)

import (
	"testing"

	"github.com/sufield/stave/internal/adapters/controls/builtin"
	"github.com/sufield/stave/internal/builtin/predicate"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
)

// --- Fixture helpers ---

func encryptBucket(id string, encryption map[string]any, tags map[string]any) asset.Asset {
	storage := map[string]any{
		"kind": "bucket",
	}
	if encryption != nil {
		storage["encryption"] = encryption
	}
	if tags != nil {
		storage["tags"] = tags
	}
	return asset.Asset{
		ID:     asset.ID(id),
		Type:   kernel.NewAssetType("aws_s3_bucket"),
		Vendor: "aws",
		Properties: map[string]any{
			"storage": storage,
		},
	}
}

func encryptSnapshot(assets ...asset.Asset) []asset.Snapshot {
	t1 := mustParseTime("2026-01-10T00:00:00Z")
	t2 := mustParseTime("2026-01-11T00:00:00Z")
	return []asset.Snapshot{
		{SchemaVersion: kernel.SchemaObservation, CapturedAt: t1, Assets: assets},
		{SchemaVersion: kernel.SchemaObservation, CapturedAt: t2, Assets: assets},
	}
}

// --- Control loader ---

func loadEncryptControls(t *testing.T) []policy.ControlDefinition {
	t.Helper()
	reg := builtin.NewControlStore(builtin.EmbeddedFS(), "embedded",
		builtin.WithAliasResolver(predicate.ResolverFunc()))
	all, err := reg.All()
	if err != nil {
		t.Fatalf("loading built-in controls: %v", err)
	}
	ids := map[kernel.ControlID]struct{}{
		"CTL.S3.ENCRYPT.001": {},
		"CTL.S3.ENCRYPT.002": {},
		"CTL.S3.ENCRYPT.003": {},
		"CTL.S3.ENCRYPT.004": {},
	}
	var controls []policy.ControlDefinition
	for _, ctl := range all {
		if _, ok := ids[ctl.ID]; ok {
			controls = append(controls, ctl)
		}
	}
	if len(controls) != len(ids) {
		t.Fatalf("expected %d encrypt controls, found %d", len(ids), len(controls))
	}
	return controls
}

func encryptEvaluator(t *testing.T) *testEvaluator {
	t.Helper()
	return NewEvaluator(
		loadEncryptControls(t),
		0,
		ports.FixedClock(mustParseTime("2026-01-11T00:00:00Z")),
	)
}

// --- Assertion helpers ---

func assertHasEncryptFinding(t *testing.T, result evaluation.Audit, controlID kernel.ControlID, assetID string) {
	t.Helper()
	for _, f := range result.Findings {
		if f.ControlID == controlID && f.AssetID == asset.ID(assetID) {
			return
		}
	}
	t.Errorf("expected finding %s for asset %s, got %d findings", controlID, assetID, len(result.Findings))
}

func assertNoEncryptFinding(t *testing.T, result evaluation.Audit, controlID kernel.ControlID, assetID string) {
	t.Helper()
	for _, f := range result.Findings {
		if f.ControlID == controlID && f.AssetID == asset.ID(assetID) {
			t.Errorf("unexpected finding %s for asset %s", controlID, assetID)
			return
		}
	}
}

// --- E2E Tests: CTL.S3.ENCRYPT.001 (Encryption at Rest) ---

func TestEncrypt001_TruePositive_NoEncryption(t *testing.T) {
	ev := encryptEvaluator(t)
	bucket := encryptBucket("unencrypted-bucket", map[string]any{
		"at_rest_enabled": false,
	}, nil)

	result := ev.Evaluate(encryptSnapshot(bucket))

	assertHasEncryptFinding(t, result, "CTL.S3.ENCRYPT.001", "unencrypted-bucket")
}

func TestEncrypt001_TrueNegative_Encrypted(t *testing.T) {
	ev := encryptEvaluator(t)
	bucket := encryptBucket("encrypted-bucket", map[string]any{
		"at_rest_enabled": true,
	}, nil)

	result := ev.Evaluate(encryptSnapshot(bucket))

	assertNoEncryptFinding(t, result, "CTL.S3.ENCRYPT.001", "encrypted-bucket")
}

// --- E2E Tests: CTL.S3.ENCRYPT.002 (Transport Encryption) ---

func TestEncrypt002_TruePositive_NoTransitEncryption(t *testing.T) {
	ev := encryptEvaluator(t)
	bucket := encryptBucket("no-tls-bucket", map[string]any{
		"in_transit_enforced": false,
	}, nil)

	result := ev.Evaluate(encryptSnapshot(bucket))

	assertHasEncryptFinding(t, result, "CTL.S3.ENCRYPT.002", "no-tls-bucket")
}

func TestEncrypt002_TrueNegative_TransitEnforced(t *testing.T) {
	ev := encryptEvaluator(t)
	bucket := encryptBucket("tls-bucket", map[string]any{
		"in_transit_enforced": true,
	}, nil)

	result := ev.Evaluate(encryptSnapshot(bucket))

	assertNoEncryptFinding(t, result, "CTL.S3.ENCRYPT.002", "tls-bucket")
}

// --- E2E Tests: CTL.S3.ENCRYPT.003 (PHI Must Use SSE-KMS with CMK) ---
// Gated by: tags.data-classification == "phi"
// Unsafe when: algorithm != "aws:kms" OR kms_key_id == ""

func TestEncrypt003_TruePositive_PHIWithAES256(t *testing.T) {
	ev := encryptEvaluator(t)
	bucket := encryptBucket("phi-aes-bucket", map[string]any{
		"algorithm":  "AES256",
		"kms_key_id": "",
	}, map[string]any{
		"data-classification": "phi",
	})

	result := ev.Evaluate(encryptSnapshot(bucket))

	assertHasEncryptFinding(t, result, "CTL.S3.ENCRYPT.003", "phi-aes-bucket")
}

func TestEncrypt003_TruePositive_PHIWithKMSButNoKey(t *testing.T) {
	ev := encryptEvaluator(t)
	bucket := encryptBucket("phi-no-key-bucket", map[string]any{
		"algorithm":  "aws:kms",
		"kms_key_id": "",
	}, map[string]any{
		"data-classification": "phi",
	})

	result := ev.Evaluate(encryptSnapshot(bucket))

	assertHasEncryptFinding(t, result, "CTL.S3.ENCRYPT.003", "phi-no-key-bucket")
}

func TestEncrypt003_TrueNegative_PHIWithKMSAndCMK(t *testing.T) {
	ev := encryptEvaluator(t)
	bucket := encryptBucket("phi-kms-bucket", map[string]any{
		"algorithm":  "aws:kms",
		"kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/example-key-id",
	}, map[string]any{
		"data-classification": "phi",
	})

	result := ev.Evaluate(encryptSnapshot(bucket))

	assertNoEncryptFinding(t, result, "CTL.S3.ENCRYPT.003", "phi-kms-bucket")
}

func TestEncrypt003_TrueNegative_NonPHIBucket(t *testing.T) {
	ev := encryptEvaluator(t)
	// Not tagged as PHI — control should not fire even with AES256
	bucket := encryptBucket("public-bucket", map[string]any{
		"algorithm":  "AES256",
		"kms_key_id": "",
	}, map[string]any{
		"data-classification": "public",
	})

	result := ev.Evaluate(encryptSnapshot(bucket))

	assertNoEncryptFinding(t, result, "CTL.S3.ENCRYPT.003", "public-bucket")
}

// --- E2E Tests: CTL.S3.ENCRYPT.004 (Sensitive Data Requires KMS) ---
// Gated by: kind=bucket AND tags.data-classification present AND not "public" AND not "non-sensitive"
// Unsafe when: algorithm != "aws:kms"

func TestEncrypt004_TruePositive_ConfidentialWithAES256(t *testing.T) {
	ev := encryptEvaluator(t)
	bucket := encryptBucket("conf-aes-bucket", map[string]any{
		"algorithm": "AES256",
	}, map[string]any{
		"data-classification": "confidential",
	})

	result := ev.Evaluate(encryptSnapshot(bucket))

	assertHasEncryptFinding(t, result, "CTL.S3.ENCRYPT.004", "conf-aes-bucket")
}

func TestEncrypt004_TrueNegative_ConfidentialWithKMS(t *testing.T) {
	ev := encryptEvaluator(t)
	bucket := encryptBucket("conf-kms-bucket", map[string]any{
		"algorithm": "aws:kms",
	}, map[string]any{
		"data-classification": "confidential",
	})

	result := ev.Evaluate(encryptSnapshot(bucket))

	assertNoEncryptFinding(t, result, "CTL.S3.ENCRYPT.004", "conf-kms-bucket")
}

func TestEncrypt004_TrueNegative_PublicClassification(t *testing.T) {
	ev := encryptEvaluator(t)
	// "public" classification is excluded from this control
	bucket := encryptBucket("public-bucket", map[string]any{
		"algorithm": "AES256",
	}, map[string]any{
		"data-classification": "public",
	})

	result := ev.Evaluate(encryptSnapshot(bucket))

	assertNoEncryptFinding(t, result, "CTL.S3.ENCRYPT.004", "public-bucket")
}

func TestEncrypt004_TrueNegative_NonSensitiveClassification(t *testing.T) {
	ev := encryptEvaluator(t)
	// "non-sensitive" classification is excluded from this control
	bucket := encryptBucket("nonsens-bucket", map[string]any{
		"algorithm": "AES256",
	}, map[string]any{
		"data-classification": "non-sensitive",
	})

	result := ev.Evaluate(encryptSnapshot(bucket))

	assertNoEncryptFinding(t, result, "CTL.S3.ENCRYPT.004", "nonsens-bucket")
}

func TestEncrypt004_TrueNegative_NoClassificationTag(t *testing.T) {
	ev := encryptEvaluator(t)
	// No data-classification tag — control should not fire
	bucket := encryptBucket("untagged-bucket", map[string]any{
		"algorithm": "AES256",
	}, nil)

	result := ev.Evaluate(encryptSnapshot(bucket))

	assertNoEncryptFinding(t, result, "CTL.S3.ENCRYPT.004", "untagged-bucket")
}
