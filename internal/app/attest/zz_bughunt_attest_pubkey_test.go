package attest

import (
	"crypto/ed25519"
	"testing"

	"github.com/sufield/stave/internal/core/asset"
)

func TestBugHunt_VerifyAssets_InvalidPublicKeyLength(t *testing.T) {
	assets := []asset.Asset{
		{ID: "arn:aws:s3:::my-bucket", Type: "aws_s3_bucket"},
	}
	attestation := &InlineAttestation{
		Signature: "YWJjZA==", // base64 for "abcd"
	}

	// Under buggy code, passing nil or an invalid length public key to VerifyAssets panics
	// because ed25519.Verify panics when key length is not exactly 32.
	// We assert that it returns a clean error instead of panicking.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("VerifyAssets panicked on invalid public key: %v", r)
		}
	}()

	err := VerifyAssets(assets, attestation, nil)
	if err == nil {
		t.Error("expected error for nil public key, got nil")
	}

	err = VerifyAssets(assets, attestation, ed25519.PublicKey([]byte("too-short")))
	if err == nil {
		t.Error("expected error for too short public key, got nil")
	}
}

func TestBugHunt_Verify_InvalidPublicKeyLength(t *testing.T) {
	// Under buggy code, passing an invalid length public key to Verify panics or executes I/O first.
	// We want it to fail fast with a clean validation error.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Verify panicked on invalid public key: %v", r)
		}
	}()

	err := Verify("nonexistent-file", nil)
	if err == nil {
		t.Error("expected error for nil public key, got nil")
	}
}
