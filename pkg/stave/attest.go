package stave

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	appatt "github.com/sufield/stave/internal/app/attest"
	"github.com/sufield/stave/internal/core/asset"
)

// SignSnapshot signs the assets in an observation snapshot (JSON) with an
// Ed25519 private key and returns the attested snapshot as indented JSON
// bytes. keyID, when non-empty, overrides the recorded public-key
// fingerprint; signedAt and hostname are stamped into the attestation.
// It is the library entry point behind `stave attest sign`.
func SignSnapshot(snapData []byte, privateKey ed25519.PrivateKey, keyID, hostname string, signedAt time.Time) ([]byte, error) {
	var snapshot struct {
		SchemaVersion string               `json:"schema_version"`
		CapturedAt    time.Time            `json:"captured_at"`
		Source        asset.SnapshotSource `json:"source"`
		Assets        []asset.Asset        `json:"assets"`
	}
	if err := json.Unmarshal(snapData, &snapshot); err != nil {
		return nil, fmt.Errorf("parse snapshot: %w", err)
	}

	attestation, err := appatt.SignAssets(snapshot.Assets, privateKey, hostname, "stave-cli", signedAt)
	if err != nil {
		return nil, fmt.Errorf("sign assets: %w", err)
	}
	if keyID != "" {
		attestation.PublicKeyFingerprint = keyID
	}

	attested := appatt.AttestedSnapshot{
		SchemaVersion: snapshot.SchemaVersion,
		CapturedAt:    snapshot.CapturedAt,
		Source:        snapshot.Source,
		Attestation:   attestation,
		Assets:        snapshot.Assets,
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(attested); err != nil {
		return nil, fmt.Errorf("encode attested snapshot: %w", err)
	}
	return buf.Bytes(), nil
}

// VerifySnapshot verifies an attested snapshot (JSON) against an Ed25519
// public key. It returns (true, nil) when the assets are intact,
// (false, nil) when verification fails (the snapshot was tampered with),
// or an error when the input cannot be parsed. It is the library entry
// point behind `stave attest verify`.
func VerifySnapshot(snapData []byte, publicKey ed25519.PublicKey) (bool, error) {
	var attested appatt.AttestedSnapshot
	if err := json.Unmarshal(snapData, &attested); err != nil {
		return false, fmt.Errorf("parse attested snapshot: %w", err)
	}
	if err := appatt.VerifyAssets(attested.Assets, attested.Attestation, publicKey); err != nil {
		//nolint:nilerr // a verification failure is a valid result (tampered), signalled by the bool, not an error.
		return false, nil
	}
	return true, nil
}

// GenerateAttestKeyPair generates an Ed25519 key pair for snapshot
// attestation. It is the library entry point behind `stave attest keygen`.
func GenerateAttestKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := appatt.GenerateKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("generate key pair: %w", err)
	}
	return pub, priv, nil
}
