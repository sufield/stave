package integrity

import (
	"encoding/json"
	"fmt"

	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/ports"
)

// Manifest defines expected per-file and aggregate hashes for integrity verification.
type Manifest struct {
	Files   map[evaluation.FilePath]kernel.Digest `json:"files"`
	Overall kernel.Digest                         `json:"overall"`
}

// SignedManifest wraps a manifest with a detached signature.
type SignedManifest struct {
	Manifest  Manifest         `json:"manifest"`
	Signature kernel.Signature `json:"signature"`
}

// canonicalManifest is a proxy struct for deterministic JSON serialization.
// encoding/json sorts map keys and emits struct fields in definition order,
// guaranteeing stable output for signing and signature verification.
type canonicalManifest struct {
	Files   map[string]string `json:"files"`
	Overall string            `json:"overall"`
}

// CanonicalBytes returns a stable byte representation of the manifest for
// signing and signature verification. It uses a proxy struct with plain
// string types so encoding/json produces deterministic compact JSON with
// sorted map keys.
func (m Manifest) CanonicalBytes() ([]byte, error) {
	proxy := canonicalManifest{
		Files:   make(map[string]string, len(m.Files)),
		Overall: string(m.Overall),
	}
	for k, v := range m.Files {
		proxy.Files[string(k)] = string(v)
	}

	data, err := json.Marshal(proxy)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical manifest: %w", err)
	}
	return data, nil
}

// VerifySignedManifest validates a detached Ed25519 signature for a manifest.
func VerifySignedManifest(sm SignedManifest, v ports.Verifier) error {
	message, err := sm.Manifest.CanonicalBytes()
	if err != nil {
		return fmt.Errorf("canonicalize manifest: %w", err)
	}
	if err = v.Verify(message, sm.Signature); err != nil {
		return fmt.Errorf("manifest signature verification failed: %w", err)
	}
	return nil
}
