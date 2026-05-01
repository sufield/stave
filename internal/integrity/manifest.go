package integrity

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
	platformcrypto "github.com/sufield/stave/internal/platform/crypto"
)

// Manifest defines expected per-file and aggregate hashes for integrity verification.
type Manifest struct {
	Files   map[evaluation.FilePath]kernel.Digest `json:"files"`
	Overall kernel.Digest                         `json:"overall"`
}

// ComputeOverall returns the aggregate digest for the Files map.
// It hashes a sorted canonical representation ("name=hash\n" per entry)
// so that the result is order-independent and tamper-evident.
func ComputeOverall(files map[evaluation.FilePath]kernel.Digest) kernel.Digest {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, string(name))
	}
	slices.Sort(names)

	var b strings.Builder
	for _, name := range names {
		fmt.Fprintf(&b, "%s=%s\n", name, files[evaluation.FilePath(name)])
	}
	return platformcrypto.HashBytes([]byte(b.String()))
}

// ValidateOverall recomputes the aggregate hash and returns an error if
// it doesn't match the stored Overall digest.
//
// Error wording: "expected" is the stored manifest value (what we
// trust), "got" is the recomputed value (what we now observe). The
// earlier shape had these swapped — diagnostics that a reader scans
// to figure out "which side changed?" pointed in the wrong
// direction. verify.go:76 already uses the corrected order.
func (m Manifest) ValidateOverall() error {
	recomputed := ComputeOverall(m.Files)
	if m.Overall != recomputed {
		return fmt.Errorf("overall hash mismatch (expected %s, got %s)", m.Overall, recomputed)
	}
	return nil
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
//
// Defense in depth: refuses to canonicalize a manifest with an
// empty Overall digest. The signing and signature-verification paths
// both flow through here, so rejecting at this gate prevents any
// caller (including ones that skip Verify's empty-Overall check)
// from producing or accepting a signed manifest whose aggregate
// digest is missing.
func (m Manifest) CanonicalBytes() ([]byte, error) {
	if m.Overall == "" {
		return nil, fmt.Errorf("%w: cannot canonicalize manifest without an Overall digest", ErrIntegrityViolation)
	}
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
// Rejects manifests with an empty Overall digest before signature
// verification proceeds: a signed-but-empty-Overall manifest would
// authenticate the *signature* but leave the per-file map
// effectively unconstrained, since Verify's aggregate check has no
// reference to compare against.
func VerifySignedManifest(sm SignedManifest, v ports.Verifier) error {
	if sm.Manifest.Overall == "" {
		return fmt.Errorf("%w: signed manifest has empty Overall digest; refusing to verify a manifest whose aggregate constraint is missing", ErrIntegrityViolation)
	}
	message, err := sm.Manifest.CanonicalBytes()
	if err != nil {
		return fmt.Errorf("canonicalize manifest: %w", err)
	}
	if err = v.Verify(message, sm.Signature); err != nil {
		return fmt.Errorf("manifest signature verification failed: %w", err)
	}
	return nil
}
