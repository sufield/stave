package ui

import (
	"errors"
	"fmt"

	"github.com/sufield/stave/internal/metadata"
)

type hintedError struct {
	hint error
	err  error
}

func (e *hintedError) Error() string {
	if e == nil || e.err == nil {
		return ""
	}
	return e.err.Error()
}

func (e *hintedError) Unwrap() []error {
	if e == nil {
		return nil
	}
	out := make([]error, 0, 2)
	if e.err != nil {
		out = append(out, e.err)
	}
	if e.hint != nil {
		out = append(out, e.hint)
	}
	return out
}

func (e *hintedError) Is(target error) bool {
	if e == nil || target == nil {
		return false
	}
	return errors.Is(e.err, target) || errors.Is(e.hint, target)
}

func (e *hintedError) As(target any) bool {
	if e == nil {
		return false
	}
	return errors.As(e.err, target) || errors.As(e.hint, target)
}

// WithHint decorates err with a sentinel hint for later rule matching.
func WithHint(err, hint error) error {
	if err == nil || hint == nil {
		return err
	}
	if errors.Is(err, hint) {
		return err
	}
	return &hintedError{hint: hint, err: err}
}

// WithNextCommand appends a remediation command to an error.
// The "More info" line resolves to a local `stave docs search` reference
// (or the URL in STAVE_DOCS_URL if set).
func WithNextCommand(err error, command string) error {
	return withNextCommandAndDocs(err, command, metadata.DocsRef("troubleshooting"))
}

// withNextCommandAndDocs is the internal variant that accepts a custom docs reference.
func withNextCommandAndDocs(err error, command, docsRef string) error {
	if err == nil || command == "" {
		return err
	}
	return fmt.Errorf("%w\nNext: %s\nMore info: %s", err, command, docsRef)
}
