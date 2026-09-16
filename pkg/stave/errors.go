package stave

import (
	appcontracts "github.com/sufield/stave/internal/core/contracts"
)

// ErrInvalidInput marks an error whose root cause is user input —
// a bad flag value, a missing required argument, an unsupported
// format. CLI commands consume this through the root command's
// exit-code shim (internal/cli/ui.ExitCode), which maps any error
// chain matching `errors.Is(err, ErrInvalidInput)` to exit code 2
// (ExitInputError).
//
// Defined in internal/core/contracts so both cli/ui and pkg/stave
// can reference the same sentinel without a circular dependency.
//
// Usage:
//
//	return fmt.Errorf("--format must be json (got %q): %w", format, stave.ErrInvalidInput)
var ErrInvalidInput = appcontracts.ErrInvalidInput

// ErrAttestationFailed marks an attestation verification failure —
// a tampered snapshot, a key mismatch, or an unsigned snapshot when
// --require-signed is set. The CLI exit-code shim maps this to exit 6
// (ExitAttestationFailed).
var ErrAttestationFailed = appcontracts.ErrAttestationFailed

// asInvalidInput tags err as a user-input error so the CLI exit-code shim maps
// it to exit 2, WITHOUT appending redundant "invalid input" text. The engine
// errors it wraps already carry an internal input sentinel in their message
// (e.g. applycmd.ErrInvalidInput); a plain `fmt.Errorf("%w: %w", err,
// ErrInvalidInput)` would render "...: invalid input: invalid input". This
// joins ErrInvalidInput into the errors.Is chain only, preserving the original
// message verbatim.
func asInvalidInput(err error) error {
	return invalidInputError{err: err}
}

type invalidInputError struct{ err error }

func (e invalidInputError) Error() string { return e.err.Error() }

func (e invalidInputError) Unwrap() error { return e.err }

func (e invalidInputError) Is(target error) bool { return target == ErrInvalidInput }
