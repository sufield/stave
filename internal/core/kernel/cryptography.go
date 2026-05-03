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

var (
	encryptionAlgorithmsMu sync.RWMutex
	encryptionAlgorithms   = []EncryptionAlgorithm{
		AlgorithmAES256,
		AlgorithmNone,
	}
)

// RegisterEncryptionAlgorithm adds algo to the registry consulted by
// ParseAlgorithm. Idempotent. Provider packages call this from
// init() so vendor-specific algorithms (e.g. GCP CMEK, Azure key
// vault) become parseable without the kernel needing to know them.
func RegisterEncryptionAlgorithm(algo EncryptionAlgorithm) {
	if algo == "" {
		return
	}
	encryptionAlgorithmsMu.Lock()
	defer encryptionAlgorithmsMu.Unlock()
	if slices.Contains(encryptionAlgorithms, algo) {
		return
	}
	encryptionAlgorithms = append(encryptionAlgorithms, algo)
}

// String returns the string representation of the algorithm.
func (a EncryptionAlgorithm) String() string { return string(a) }

// ParseAlgorithm normalizes and validates a string into an EncryptionAlgorithm.
func ParseAlgorithm(raw string) (EncryptionAlgorithm, error) {
	norm := EncryptionAlgorithm(strings.ToLower(strings.TrimSpace(raw)))
	encryptionAlgorithmsMu.RLock()
	defer encryptionAlgorithmsMu.RUnlock()
	if slices.Contains(encryptionAlgorithms, norm) {
		return norm, nil
	}
	return "", fmt.Errorf("unsupported encryption algorithm: %q", raw)
}
