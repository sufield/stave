package json

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/integrity"
	"github.com/sufield/stave/internal/platform/fsutil"
)

func (l *ObservationLoader) verifyConfiguredIntegrity(hashes *evaluation.InputHashes) error {
	if strings.TrimSpace(l.integrityManifestPath) == "" {
		return nil
	}

	manifestData, err := fsutil.ReadFileLimited(l.integrityManifestPath)
	if err != nil {
		return fmt.Errorf("read integrity manifest: %w", err)
	}

	m, err := l.loadManifest(manifestData)
	if err != nil {
		return err
	}

	validator := integrity.Validator{ActualHashes: hashes}
	return validator.Verify(m)
}

// loadManifest parses a manifest, verifying the signature when a public key is configured.
func (l *ObservationLoader) loadManifest(data []byte) (integrity.Manifest, error) {
	if strings.TrimSpace(l.integrityPublicKeyPath) != "" {
		return loadSignedManifest(data, l.integrityPublicKeyPath)
	}

	var m integrity.Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return integrity.Manifest{}, fmt.Errorf("parse integrity manifest: %w", err)
	}
	return m, nil
}

// loadSignedManifest reads the public key and verifies a signed manifest.
func loadSignedManifest(data []byte, publicKeyPath string) (integrity.Manifest, error) {
	pubKey, err := fsutil.ReadFileLimited(publicKeyPath)
	if err != nil {
		return integrity.Manifest{}, fmt.Errorf("read integrity public key: %w", err)
	}
	return integrity.UnmarshalSigned(data, pubKey)
}
