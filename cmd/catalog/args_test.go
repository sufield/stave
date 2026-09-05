package catalog

import (
	"bytes"
	"errors"
	"testing"

	"github.com/sufield/stave/internal/cli/ui"
)

// TestArgs_SurplusPositionalIsUserError pins the command's arg handling: a
// surplus positional argument is invalid input (exit 2), not an internal
// error (exit 4). The wrapped Args validator must return a *ui.UserError so
// the executor maps it to ExitInputError. (Rendering coverage moved to
// pkg/stave with the facade.)
func TestArgs_SurplusPositionalIsUserError(t *testing.T) {
	cmd := NewCmd() // RunE is never reached: Args fails first
	cmd.SetArgs([]string{"s3", "iam"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected an error for two positional args")
	}
	if _, ok := errors.AsType[*ui.UserError](err); !ok {
		t.Errorf("surplus-arg error must be *ui.UserError (-> exit 2), got %T: %v", err, err)
	}
}
