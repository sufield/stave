package ui

import (
	"fmt"
	"os"
)

// DirectoryAccessError returns a user-facing error for missing or inaccessible
// directories. The hint parameter associates a remediation hint sentinel for
// downstream suggestion matching; pass nil when no specific hint applies.
func DirectoryAccessError(flagName, path string, err error, hint error) error {
	prefix := fmt.Sprintf("%s not accessible: %s", flagName, path)

	switch {
	case os.IsNotExist(err):
		msg := fmt.Errorf("%s: directory does not exist (check the path or create it)", prefix)
		return WithHint(msg, hint)
	case os.IsPermission(err):
		msg := fmt.Errorf("%s: permission denied (check directory read/execute bits)", prefix)
		return WithHint(msg, hint)
	default:
		return WithHint(fmt.Errorf("%s: %w", prefix, err), hint)
	}
}
