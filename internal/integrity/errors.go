// Package integrity provides manifest-based file integrity verification.
package integrity

import "errors"

// ErrIntegrityViolation is returned when an integrity check detects a mismatch.
var ErrIntegrityViolation = errors.New("integrity violation")
