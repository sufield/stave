package evaluation

import (
	"time"

	"github.com/sufield/stave/internal/core/kernel"
)

// Metadata holds typed provenance for an evaluation run: how controls were
// selected, where they came from, and the state of the source repository.
type Metadata struct {
	ContextName   string             `json:"context_name"`
	ControlSource ControlSourceInfo  `json:"control_source"`
	ResolvedPaths ResolvedPaths      `json:"resolved_paths"`
	Integrity     *IntegrityStatus   `json:"integrity,omitempty"`
	Attestation   *AttestationStatus `json:"attestation,omitempty"`
}

// IntegrityStatus records whether observation integrity was verified.
type IntegrityStatus struct {
	Verified       bool      `json:"verified"`
	ManifestPath   string    `json:"manifest_path,omitempty"`
	KeyFingerprint string    `json:"key_fingerprint,omitempty"`
	VerifiedAt     time.Time `json:"verified_at,omitzero"`
}

// AttestationStatusValue identifies the outcome of snapshot attestation verification.
type AttestationStatusValue string

const (
	AttestationUnsigned AttestationStatusValue = "UNSIGNED"
	AttestationVerified AttestationStatusValue = "VERIFIED"
	AttestationFailed   AttestationStatusValue = "FAILED"
)

// AttestationStatus records whether observation snapshots were attested (Ed25519 signed).
type AttestationStatus struct {
	Status         AttestationStatusValue `json:"status"`
	KeyFingerprint string                 `json:"key_fingerprint,omitempty"`
	SignedAt       string                 `json:"signed_at,omitempty"`
}

// ControlSourceMode identifies how controls were selected for evaluation.
type ControlSourceMode string

// ControlSourceDir and related constants.
const (
	// ControlSourceDir constants.
	ControlSourceDir   ControlSourceMode = "dir"
	ControlSourcePacks ControlSourceMode = "packs"
)

// ControlSourceInfo records which controls were loaded and from where.
type ControlSourceInfo struct {
	Source             ControlSourceMode  `json:"source"`
	EnabledPacks       []kernel.PackName  `json:"enabled_packs,omitempty"`
	ResolvedControlIDs []kernel.ControlID `json:"resolved_control_ids,omitempty"`
	RegistryVersion    string             `json:"registry_version,omitempty"`
	RegistryHash       kernel.Digest      `json:"registry_hash,omitempty"`
}

// ResolvedPaths records the absolute paths used for controls and observations.
type ResolvedPaths struct {
	Controls     string `json:"controls"`
	Observations string `json:"observations"`
}
