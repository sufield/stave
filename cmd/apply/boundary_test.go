package apply

import (
	"strings"
	"testing"
)

// TestApplyDryRunContract verifies that apply help references --dry-run.
func TestApplyDryRunContract(t *testing.T) {
	helpText := NewApplyCmd().Long
	if !strings.Contains(helpText, "--dry-run") {
		t.Error("apply help text should reference --dry-run")
	}
}
