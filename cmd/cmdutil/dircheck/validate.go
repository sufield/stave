package dircheck

import (
	"fmt"
	"os"

	"github.com/sufield/stave/cmd/cmdutil/projctx"
	"github.com/sufield/stave/internal/cli/ui"
)

// CheckDir verifies that the given path exists and is a directory.
// It returns a standard error without CLI-specific formatting, making it
// suitable for use in internal packages.
func CheckDir(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("path is not a directory: %s", path)
	}
	return nil
}

// ValidateFlagDir is a CLI helper that validates a directory path associated
// with a flag. If validation fails, it enriches the error with UI-specific
// hints and any available path-inference diagnostics.
func ValidateFlagDir(flag, path, inferKey string, hint error, log *projctx.InferenceLog) error {
	if err := CheckDir(path); err != nil {
		err = ui.DirectoryAccessError(flag, path, err, hint)

		if log != nil {
			if detail := log.Explain(inferKey); detail != "" {
				return fmt.Errorf("%w\n%s", err, detail)
			}
		}

		return err
	}
	return nil
}
