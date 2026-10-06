package attest

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestSignVerifyAssets_Roundtrip(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	assets := []asset.Asset{
		{ID: "arn:aws:s3:::test-bucket", Type: kernel.AssetType("s3_bucket"),
			Properties: map[string]any{"versioning": true}},
	}

	attestation, err := SignAssets(assets, priv, "collector-01", "stave v0.0.5", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifyAssets(assets, attestation, pub); err != nil {
		t.Errorf("verification failed on untampered assets: %v", err)
	}
}

func TestVerifyAssets_TamperedFails(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	assets := []asset.Asset{
		{ID: "arn:aws:s3:::test-bucket", Type: "s3_bucket",
			Properties: map[string]any{"versioning": true}},
	}

	attestation, err := SignAssets(assets, priv, "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with the assets.
	assets[0].Properties["versioning"] = false

	if err := VerifyAssets(assets, attestation, pub); err == nil {
		t.Error("expected verification failure on tampered assets")
	}
}

func TestVerifyAssets_NoAttestation(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	assets := []asset.Asset{{ID: "test"}}

	if err := VerifyAssets(assets, nil, pub); err == nil {
		t.Error("expected error for nil attestation")
	}
}

func TestKeyFingerprint_DomainMethods(t *testing.T) {
	pub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	fp := KeyFingerprint("sha256:1234567890abcdef")
	if fp.String() != "sha256:1234567890abcdef" {
		t.Errorf("String() = %q, want %q", fp.String(), "sha256:1234567890abcdef")
	}
	if fp.IsEmpty() {
		t.Errorf("IsEmpty() returned true for non-empty fingerprint")
	}
	if !fp.HasPrefix("sha256:") {
		t.Errorf("HasPrefix(\"sha256:\") returned false")
	}
	if fp.Digest() != "1234567890abcdef" {
		t.Errorf("Digest() = %q, want %q", fp.Digest(), "1234567890abcdef")
	}

	emptyFp := KeyFingerprint("   ")
	if !emptyFp.IsEmpty() {
		t.Errorf("IsEmpty() returned false for whitespace fingerprint")
	}
	if !emptyFp.MatchesPublicKey(pub) {
		t.Errorf("MatchesPublicKey() returned false for empty fingerprint")
	}
}
