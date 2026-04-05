// Package apply provides application-layer support for the apply command
// including user guidance and hint generation.
package apply

import (
	"os"
	"path/filepath"
	"strings"
)

// ResolveContextName provides the default logic for naming the evaluation run.
// It is pure — it doesn't look at global state, only its inputs.
func ResolveContextName(projectRoot string, selectedContext string) string {
	if strings.TrimSpace(selectedContext) != "" {
		return strings.TrimSpace(selectedContext)
	}

	base := filepath.Base(projectRoot)
	if base == "" || base == "." || base == string(os.PathSeparator) {
		return "default"
	}
	return base
}
