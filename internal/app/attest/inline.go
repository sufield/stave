package attest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/sufield/stave/internal/core/asset"
)

// InlineAttestation is the attestation field embedded in observation JSON.
type InlineAttestation struct {
	SignedAt             string `json:"signed_at"`
	CollectorHostname    string `json:"collector_hostname,omitempty"`
	CollectorVersion     string `json:"collector_version,omitempty"`
	SignatureAlgorithm   string `json:"signature_algorithm"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
	Signature            string `json:"signature"`
}

// AttestedSnapshot wraps a snapshot with its attestation.
type AttestedSnapshot struct {
	SchemaVersion string               `json:"schema_version"`
	CapturedAt    time.Time            `json:"captured_at"`
	Source        asset.SnapshotSource `json:"source"`
	Attestation   *InlineAttestation   `json:"attestation,omitempty"`
	Assets        []asset.Asset        `json:"assets"`
}

// SignAssets signs the canonical JSON of the assets array and returns
// an InlineAttestation. The signature covers only the assets, not the
// attestation field itself.
func SignAssets(assets []asset.Asset, privateKey ed25519.PrivateKey, hostname, version string, signedAt time.Time) (*InlineAttestation, error) {
	canonical, err := json.Marshal(assets)
	if err != nil {
		return nil, fmt.Errorf("marshal assets: %w", err)
	}

	sig := ed25519.Sign(privateKey, canonical)
	pubKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("private key does not produce Ed25519 public key")
	}
	fingerprint := sha256.Sum256(pubKey)

	return &InlineAttestation{
		SignedAt:             signedAt.UTC().Format(time.RFC3339),
		CollectorHostname:    hostname,
		CollectorVersion:     version,
		SignatureAlgorithm:   "Ed25519",
		PublicKeyFingerprint: "sha256:" + hex.EncodeToString(fingerprint[:]),
		Signature:            base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// VerifyAssets checks an inline attestation against the assets array.
func VerifyAssets(assets []asset.Asset, attestation *InlineAttestation, publicKey ed25519.PublicKey) error {
	if attestation == nil {
		return errors.New("no attestation present")
	}

	canonical, err := json.Marshal(assets)
	if err != nil {
		return fmt.Errorf("marshal assets for verification: %w", err)
	}

	sigBytes, decErr := base64.StdEncoding.DecodeString(attestation.Signature)
	if decErr != nil {
		return fmt.Errorf("decode signature: %w", decErr)
	}

	if !ed25519.Verify(publicKey, canonical, sigBytes) {
		return errors.New("attestation signature verification failed — assets may have been tampered")
	}

	return nil
}

// GenerateKeyPair creates a new Ed25519 key pair for snapshot attestation.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key pair: %w", err)
	}
	return pub, priv, nil
}
