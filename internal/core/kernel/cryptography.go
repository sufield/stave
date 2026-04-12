package kernel

import (
	"fmt"
	"strings"
)

// EncryptionAlgorithm represents a standardized name for a cryptographic
// cipher used in cloud storage and backup encryption.
type EncryptionAlgorithm string

const (
	// AlgorithmAWSKMS is the AWS KMS-managed encryption algorithm.
	// This is the required algorithm for PHI and classified data.
	AlgorithmAWSKMS EncryptionAlgorithm = "aws:kms"

	// AlgorithmAES256 is the S3-managed AES-256 encryption (SSE-S3).
	// Acceptable for general data but insufficient for PHI compliance.
	AlgorithmAES256 EncryptionAlgorithm = "aes256"

	// AlgorithmNone represents an unencrypted state.
	AlgorithmNone EncryptionAlgorithm = "none"
)

// String returns the string representation of the algorithm.
func (a EncryptionAlgorithm) String() string { return string(a) }

// ParseAlgorithm normalizes and validates a string into an EncryptionAlgorithm.
func ParseAlgorithm(raw string) (EncryptionAlgorithm, error) {
	norm := EncryptionAlgorithm(strings.ToLower(strings.TrimSpace(raw)))
	switch norm {
	case AlgorithmAWSKMS, AlgorithmAES256, AlgorithmNone:
		return norm, nil
	default:
		return "", fmt.Errorf("unsupported encryption algorithm: %q", raw)
	}
}
