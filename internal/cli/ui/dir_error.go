package ui

import (
	"errors"
	"fmt"
	"os"
)

// DirectoryAccessError returns a structured, user-friendly error explaining why
// a directory is inaccessible. It associates the error with a remediation hint.
func DirectoryAccessError(flagName, path string, err error, hint error) error {
	if err == nil {
		return nil
	}

	var msg error
	switch {
	case errors.Is(err, os.ErrNotExist):
		msg = fmt.Errorf("%s path %q does not exist: verify the path or create the directory",
			flagName, path)
	case errors.Is(err, os.ErrPermission):
		msg = fmt.Errorf("%s path %q permission denied: check directory read and execute bits",
			flagName, path)
	default:
		// Wrap the original error to preserve the underlying cause for debugging.
		msg = fmt.Errorf("%s path %q is not accessible: %w",
			flagName, path, err)
	}

	// WithHint attaches remediation sentinels to the error chain.
	return WithHint(msg, hint)
}
