// Package integrity provides manifest-based file integrity verification.
package integrity

import (
	"errors"
	"fmt"
)

// ErrIntegrityViolation is returned when an integrity check detects a mismatch.
// Specific sentinels below wrap this error so callers can match either the
// category (errors.Is(err, ErrIntegrityViolation)) or the specific failure.
var (
	ErrIntegrityViolation = errors.New("integrity violation")
	ErrHashMismatch       = fmt.Errorf("%w: file hash mismatch", ErrIntegrityViolation)
	ErrUntrustedFile      = fmt.Errorf("%w: untrusted file found", ErrIntegrityViolation)
	ErrMissingFile        = fmt.Errorf("%w: required file missing", ErrIntegrityViolation)
)
