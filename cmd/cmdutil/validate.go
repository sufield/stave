package cmdutil

import (
	"fmt"
	"os"

	"github.com/sufield/stave/internal/cli/ui"
)

// ValidateDir checks that path exists and is a directory.
// hint is passed to ui.DirectoryAccessError (may be nil).
func ValidateDir(flag, path string, hint error) error {
	fi, err := os.Stat(path)
	if err != nil {
		return ui.DirectoryAccessError(flag, path, err, hint)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s must be a directory: %s", flag, path)
	}
	return nil
}

// ValidateDirWithInference validates a directory and, on failure, appends any
// inference-failure explanation for the given inferKey (e.g. "controls" or
// "observations"). This pattern was previously duplicated across apply,
// diagnose, and validate command packages.
func ValidateDirWithInference(flag, path, inferKey string, hint error) error {
	if err := ValidateDir(flag, path, hint); err != nil {
		if detail := ExplainInferenceFailure(inferKey); detail != "" {
			return fmt.Errorf("%w\n%s", err, detail)
		}
		return err
	}
	return nil
}
