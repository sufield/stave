package aliases

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
)

func TestRun_DefaultCategory(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	if err := run(cmd, ""); err != nil {
		t.Fatalf("run error: %v", err)
	}
}
