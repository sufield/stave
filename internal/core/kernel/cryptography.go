package kernel

import (
	"fmt"
	"slices"
	"strings"
	"sync"
)

// EncryptionAlgorithm represents a standardized name for a cryptographic
// cipher used in cloud storage and backup encryption.
type EncryptionAlgorithm string

const (
	// AlgorithmAES256 is the S3-managed AES-256 encryption (SSE-S3).
	// Vendor-neutral: a primitive cipher name, not an AWS service.
	AlgorithmAES256 EncryptionAlgorithm = "aes256"

	// AlgorithmNone represents an unencrypted state.
	AlgorithmNone EncryptionAlgorithm = "none"
)

// String returns the string representation of the algorithm.
func (a EncryptionAlgorithm) String() string { return string(a) }

// algorithmRegistry is the concurrency-safe set of recognized encryption
// algorithms: the vendor-neutral built-ins plus any provider registrations
// (see internal/platform/providers/aws.Register). Bundling the slice with the
// RWMutex that guards it keeps the lock and the data it protects in one type,
// so the set can only be read or mutated through a method — there is no loose
// package-level mutex to lock incorrectly.
type algorithmRegistry struct {
	mu    sync.RWMutex
	algos []EncryptionAlgorithm
}

// register adds algo to the set. Idempotent; empty input is ignored.
func (r *algorithmRegistry) register(algo EncryptionAlgorithm) {
	if algo == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !slices.Contains(r.algos, algo) {
		r.algos = append(r.algos, algo)
	}
}

// parse normalizes raw and returns the matching algorithm, or an error.
func (r *algorithmRegistry) parse(raw string) (EncryptionAlgorithm, error) {
	norm := EncryptionAlgorithm(strings.ToLower(strings.TrimSpace(raw)))
	r.mu.RLock()
	defer r.mu.RUnlock()
	if slices.Contains(r.algos, norm) {
		return norm, nil
	}
	return "", fmt.Errorf("unsupported encryption algorithm: %q", raw)
}

// algorithms is the process-wide encryption-algorithm registry — the one
// remaining package-level value here, a cohesive registry instance rather than
// a loose mutex+slice pair. (Fully eliminating it would mean injecting the
// kernel's vendor registries through every reader, a kernel-wide change across
// all of them, not a per-file one.)
var algorithms = &algorithmRegistry{
	algos: []EncryptionAlgorithm{AlgorithmAES256, AlgorithmNone},
}

// RegisterEncryptionAlgorithm adds algo to the registry consulted by
// ParseAlgorithm. Idempotent. Provider packages call this from their Register()
// entrypoint (e.g. providers/aws.Register) so vendor-specific algorithms (e.g.
// GCP CMEK, Azure key vault) become parseable without the kernel needing to
// know them.
func RegisterEncryptionAlgorithm(algo EncryptionAlgorithm) {
	algorithms.register(algo)
}

// ParseAlgorithm normalizes and validates a string into an EncryptionAlgorithm.
func ParseAlgorithm(raw string) (EncryptionAlgorithm, error) {
	return algorithms.parse(raw)
}
