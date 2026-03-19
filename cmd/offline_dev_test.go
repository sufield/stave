//go:build stavedev

package cmd

import (
	"strings"
	"testing"
)

// TestOfflineHelpSuffix_DevCommands verifies dev-only commands that should
// display the offline guarantee.
func TestOfflineHelpSuffix_DevCommands(t *testing.T) {
	root := GetDevRootCmd()

	required := [][]string{
		{"doctor"},
		{"bug-report"},
		{"controls"},
		{"capabilities"},
	}

	for _, path := range required {
		cmd, _, err := root.Find(path)
		if err != nil {
			t.Errorf("dev command path %v not found: %v", path, err)
			continue
		}
		long := cmd.Long
		if !strings.Contains(long, "Offline-only") {
			t.Errorf("%v: Long help does not contain 'Offline-only'", path)
		}
	}
}
