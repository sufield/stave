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
