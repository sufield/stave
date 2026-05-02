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
