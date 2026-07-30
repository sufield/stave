package cmderr

// InputError marks a user-input failure (bad format, missing file, invalid
// flag value). Callers in pkg/stave type-assert on *InputError to map the
// error to exit code 2.
type InputError struct{ Err error }

func (e *InputError) Error() string { return e.Err.Error() }

func (e *InputError) Unwrap() error { return e.Err }
