package contracts

import "errors"

// ErrViolationsFound signals that the operation completed but violations were detected.
var ErrViolationsFound = errors.New("violations found")

// ErrValidationFailed signals that validation produced one or more
// errors, OR (under strict mode) one or more warnings. The
// validation package's Report.ExitError method returns this to
// caller-side gating code; cli/ui re-exports it as
// ui.ErrValidationFailed so existing exit-code mapping continues to
// work via errors.Is.
var ErrValidationFailed = errors.New("validation failed")

// ErrValidationWarnings signals that validation produced warnings
// only (no errors) and the caller is in non-strict mode. Sibling of
// ErrValidationFailed; same re-export pattern in cli/ui.
var ErrValidationWarnings = errors.New("validation warnings")

// ErrInvalidInput marks user-input errors (bad flags, missing args,
// unsupported formats). CLI maps errors.Is matches to exit code 2.
var ErrInvalidInput = errors.New("invalid input")

// ErrAttestationFailed marks attestation verification failures
// (tampered snapshots, key mismatches). CLI maps to exit code 6.
var ErrAttestationFailed = errors.New("attestation verification failed")

// ErrFailingTests signals that control tests completed but at least
// one test case did not match its expected verdict. CLI maps to exit 3.
var ErrFailingTests = errors.New("control tests failed")
