// Package attest provides snapshot tamper detection via Ed25519 signatures.
package attest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/sufield/stave/internal/platform/fsutil"
)

// Signature is the .sig sidecar file format.
type Signature struct {
	SchemaVersion string `json:"schema_version"`
	KeyID         string `json:"key_id"`
	Algorithm     string `json:"algorithm"`
	SignedAt      string `json:"signed_at"`
	SnapshotSHA   string `json:"snapshot_sha256"`
	Signature     string `json:"signature"`
}

// Sign produces an Ed25519 signature for a snapshot file.
// Sign produces an Ed25519 signature for a snapshot file.
func Sign(snapshotPath string, privateKey ed25519.PrivateKey, keyID, signedAt string) (*Signature, error) {
	data, err := os.ReadFile(snapshotPath) //nolint:gosec // G304: snapshotPath is caller-supplied; CLI validates via fsutil.CleanUserPath
	if err != nil {
		return nil, fmt.Errorf("read snapshot: %w", err)
	}

	hash := sha256.Sum256(data)
	hashHex := hex.EncodeToString(hash[:])

	sig := ed25519.Sign(privateKey, data)

	return &Signature{
		SchemaVersion: "1",
		KeyID:         keyID,
		Algorithm:     "ed25519",
		SignedAt:      signedAt,
		SnapshotSHA:   hashHex,
		Signature:     base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// Verify checks an Ed25519 signature against a snapshot file.
func Verify(snapshotPath string, publicKey ed25519.PublicKey) error {
	data, err := os.ReadFile(snapshotPath) //nolint:gosec // G304: snapshotPath is caller-supplied; CLI validates via fsutil.CleanUserPath
	if err != nil {
		return fmt.Errorf("read snapshot: %w", err)
	}

	sigPath := snapshotPath + ".sig"
	sigData, err := os.ReadFile(sigPath) //nolint:gosec // G304: sigPath is derived from validated snapshotPath
	if err != nil {
		return fmt.Errorf("signature file missing %s: %w", sigPath, err)
	}

	var sig Signature
	if unmarshalErr := json.Unmarshal(sigData, &sig); unmarshalErr != nil {
		return fmt.Errorf("parse signature: %w", unmarshalErr)
	}

	// Verify SHA-256 matches.
	hash := sha256.Sum256(data)
	hashHex := hex.EncodeToString(hash[:])
	if hashHex != sig.SnapshotSHA {
		return fmt.Errorf("snapshot SHA-256 mismatch: expected %s, got %s (file may have been tampered)", sig.SnapshotSHA, hashHex)
	}

	// Verify Ed25519 signature.
	sigBytes, decErr := base64.StdEncoding.DecodeString(sig.Signature)
	if decErr != nil {
		return fmt.Errorf("decode signature: %w", decErr)
	}

	if !ed25519.Verify(publicKey, data, sigBytes) {
		return fmt.Errorf("Ed25519 signature verification failed (key_id: %s)", sig.KeyID)
	}

	return nil
}

// WriteSig writes the signature sidecar file.
func WriteSig(snapshotPath string, sig *Signature) error {
	data, err := json.MarshalIndent(sig, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal signature: %w", err)
	}
	if err = fsutil.SafeWriteFile(snapshotPath+".sig", data, fsutil.ConfigWriteOpts()); err != nil {
		return fmt.Errorf("write signature file: %w", err)
	}
	return nil
}
