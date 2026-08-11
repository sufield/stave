package stave

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	appatt "github.com/sufield/stave/internal/app/attest"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/platform/fsutil"
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
	if len(snapshot.Assets) == 0 {
		return nil, errors.New("file contains no assets array — stave attest sign operates on observation snapshots, not assessment output")
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

// LoadPublicKeyPEM reads an Ed25519 public key from a PEM file.
func LoadPublicKeyPEM(path string) (ed25519.PublicKey, error) {
	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("key is not Ed25519")
	}
	return pub, nil
}

// VerifyObservationsDir verifies Ed25519 attestation on all observation
// files in a directory. Returns the overall attestation status. If any
// file's verification fails, status is FAILED with an error describing
// which file was tampered. If all files are attested and verified,
// status is VERIFIED. If no files have attestation, status is UNSIGNED.
func VerifyObservationsDir(dir string, publicKey ed25519.PublicKey) (*evaluation.AttestationStatus, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read observations dir: %w", err)
	}
	entries = slices.DeleteFunc(entries, func(e os.DirEntry) bool {
		return e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".json")
	})
	if len(entries) == 0 {
		return &evaluation.AttestationStatus{Status: evaluation.AttestationUnsigned}, nil
	}

	var lastSignedAt string
	var lastFingerprint string
	attestedCount := 0

	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		data, readErr := fsutil.ReadFileLimited(path)
		if readErr != nil {
			return nil, fmt.Errorf("read %s: %w", path, readErr)
		}

		att, hasAtt := probeAttestation(data)
		if !hasAtt {
			continue
		}

		verified, verErr := VerifySnapshot(data, publicKey)
		if verErr != nil {
			return &evaluation.AttestationStatus{Status: evaluation.AttestationFailed},
				fmt.Errorf("attestation parse error in %s: %w", entry.Name(), verErr)
		}
		if !verified {
			return &evaluation.AttestationStatus{Status: evaluation.AttestationFailed},
				fmt.Errorf("attestation verification failed for %s — assets may have been tampered", entry.Name())
		}

		attestedCount++
		lastSignedAt = att.SignedAt
		lastFingerprint = att.PublicKeyFingerprint
	}

	if attestedCount == 0 {
		return &evaluation.AttestationStatus{Status: evaluation.AttestationUnsigned}, nil
	}

	return &evaluation.AttestationStatus{
		Status:         evaluation.AttestationVerified,
		KeyFingerprint: lastFingerprint,
		SignedAt:       lastSignedAt,
	}, nil
}

// CheckObservationsAttested scans an observations directory and reports
// whether any snapshot file contains an inline attestation field.
func CheckObservationsAttested(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, fmt.Errorf("read observations dir: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			continue
		}
		data, readErr := fsutil.ReadFileLimited(filepath.Join(dir, entry.Name()))
		if readErr != nil {
			return false, readErr
		}
		if _, has := probeAttestation(data); has {
			return true, nil
		}
	}
	return false, nil
}

// probeAttestation checks whether raw JSON contains an inline attestation field.
func probeAttestation(data []byte) (*appatt.InlineAttestation, bool) {
	var probe struct {
		Attestation *appatt.InlineAttestation `json:"attestation"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, false
	}
	if probe.Attestation == nil || probe.Attestation.Signature == "" {
		return nil, false
	}
	return probe.Attestation, true
}
