package stave

import "errors"

// ErrInvalidInput marks an error whose root cause is user input —
// a bad flag value, a missing required argument, an unsupported
// format. CLI commands consume this through the root command's
// exit-code shim (internal/cli/ui.ExitCode), which maps any error
// chain matching `errors.Is(err, ErrInvalidInput)` to exit code 2
// (ExitInputError).
//
// Why this is here, not in internal/cli/ui:
//   - Commands that have migrated to the facade (cmd/score,
//     cmd/exportinvariants, …) cannot import internal/cli/ui per
//     the architecture test. They need a public sentinel they
//     can wrap into their error chains via `fmt.Errorf(... %w,
//     stave.ErrInvalidInput)` while keeping their exit-code
//     semantics intact.
//   - The internal cli/ui package imports pkg/stave for this
//     sentinel — single-direction dependency, no cycle.
//
// Usage:
//
//	return fmt.Errorf("--format must be json (got %q): %w", format, stave.ErrInvalidInput)
//
// The wrapped error chain prints the user-facing message; the
// sentinel sits behind it for the exit-code matcher to find.
//
// Other sentinels follow the same naming convention as needed —
// see ErrControlNotFound in explain.go for the per-feature
// "not-found" precedent.
var ErrInvalidInput = errors.New("invalid input")
