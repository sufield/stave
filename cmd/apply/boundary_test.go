package apply

import (
	"strings"
	"testing"

	"github.com/sufield/stave/cmd/cmdutil/compose"
)

func testApplyDeps() Deps {
	f := compose.DefaultFactories()
	return Deps{
		NewObsRepo:       f.NewObsRepo,
		NewCtlRepo:       f.NewCtlRepo,
		NewStdinObsRepo:  f.NewStdinObsRepo,
		NewFindingWriter: f.NewFindingWriter,
		NewCELEvaluator:  f.NewCELEvaluator,
	}
}

// TestApplyDryRunContract verifies that apply help references --dry-run.
func TestApplyDryRunContract(t *testing.T) {
	helpText := NewApplyCmd(testApplyDeps()).Long
	if !strings.Contains(helpText, "--dry-run") {
		t.Error("apply help text should reference --dry-run")
	}
}
