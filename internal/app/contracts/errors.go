package contracts

import "errors"

// ErrViolationsFound signals that the operation completed but violations were detected.
var ErrViolationsFound = errors.New("violations found")
