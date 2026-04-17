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
