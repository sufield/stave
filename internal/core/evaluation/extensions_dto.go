package evaluation

import (
	"slices"
	"time"

	"github.com/sufield/stave/internal/core/kernel"
)

// Extensions represents the typed JSON structure for the out.v0.1 extensions block.
// This is the stable external contract — internal Metadata is projected into it.
type Extensions struct {
	SelectedSource      string             `json:"selected_controls_source,omitempty"`
	ContextName         string             `json:"context_name,omitempty"`
	ResolvedPaths       map[string]string  `json:"resolved_paths,omitempty"`
	EnabledPacks        []kernel.PackName  `json:"enabled_control_packs,omitempty"`
	ResolvedControlIDs  []kernel.ControlID `json:"resolved_control_ids,omitempty"`
	PackRegistryVersion string             `json:"pack_registry_version,omitempty"`
	PackRegistryHash    kernel.Digest      `json:"pack_registry_hash,omitempty"`
	Integrity           *ExtIntegrity      `json:"integrity,omitempty"`
	Attestation         *ExtAttestation    `json:"attestation,omitempty"`
}

// ExtIntegrity surfaces observation integrity verification status.
// Present only when --integrity-manifest was used and verification passed.
type ExtIntegrity struct {
	Verified       bool      `json:"verified"`
	ManifestPath   string    `json:"manifest_path,omitempty"`
	KeyFingerprint string    `json:"key_fingerprint,omitempty"`
	VerifiedAt     time.Time `json:"verified_at,omitzero"`
}

// ExtAttestation surfaces snapshot attestation (Ed25519 signature) status.
type ExtAttestation struct {
	Status         string `json:"status"`
	KeyFingerprint string `json:"key_fingerprint,omitempty"`
	SignedAt       string `json:"signed_at,omitempty"`
}

// ToExtensions projects the internal Metadata into the report-friendly Extensions DTO.
// Returns nil if the Metadata is empty (uninitialized source).
func (m Metadata) ToExtensions() *Extensions {
	if m.ControlSource.Source == "" {
		return nil
	}

	ext := &Extensions{
		SelectedSource: string(m.ControlSource.Source),
		ContextName:    m.ContextName,
		ResolvedPaths: map[string]string{
			"controls":     m.ResolvedPaths.Controls,
			"observations": m.ResolvedPaths.Observations,
		},
	}

	if m.ControlSource.Source == ControlSourcePacks {
		ext.EnabledPacks = slices.Clone(m.ControlSource.EnabledPacks)
		ext.ResolvedControlIDs = slices.Clone(m.ControlSource.ResolvedControlIDs)
		ext.PackRegistryVersion = m.ControlSource.RegistryVersion
		ext.PackRegistryHash = m.ControlSource.RegistryHash
	}

	if m.Integrity != nil {
		ext.Integrity = &ExtIntegrity{
			Verified:       m.Integrity.Verified,
			ManifestPath:   m.Integrity.ManifestPath,
			KeyFingerprint: m.Integrity.KeyFingerprint,
			VerifiedAt:     m.Integrity.VerifiedAt,
		}
	}

	if m.Attestation != nil {
		ext.Attestation = &ExtAttestation{
			Status:         string(m.Attestation.Status),
			KeyFingerprint: m.Attestation.KeyFingerprint,
			SignedAt:       m.Attestation.SignedAt,
		}
	}

	return ext
}
