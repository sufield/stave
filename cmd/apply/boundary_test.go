package apply

import (
	"strings"
	"testing"

	"github.com/sufield/stave/cmd/cmdutil/compose"
)

// TestApplyDryRunContract verifies that apply help references --dry-run.
func TestApplyDryRunContract(t *testing.T) {
	helpText := NewApplyCmd(compose.NewDefaultProvider()).Long
	if !strings.Contains(helpText, "--dry-run") {
		t.Error("apply help text should reference --dry-run")
	}
}
