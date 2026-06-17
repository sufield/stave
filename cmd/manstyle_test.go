package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestManHelpTemplate_Renders guards the man-page-style help template: it only
// activates on an interactive terminal, so a syntax error in it would never
// surface in non-TTY CI. Render it explicitly against a command tree and assert
// the man sections appear and rendering does not error.
func TestManHelpTemplate_Renders(t *testing.T) {
	t.Parallel()

	root := &cobra.Command{
		Use:     "tool",
		Short:   "do things",
		Long:    "Tool does things and explains how.",
		Example: "  tool sub --flag",
		Run:     func(*cobra.Command, []string) {},
	}
	root.Flags().String("flag", "", "a local flag")
	root.PersistentFlags().Bool("verbose", false, "a global flag")
	root.AddCommand(&cobra.Command{
		Use:   "sub",
		Short: "a subcommand",
		Run:   func(*cobra.Command, []string) {},
	})

	root.SetHelpTemplate(manHelpTemplate)
	var buf bytes.Buffer
	root.SetOut(&buf)
	if err := root.Help(); err != nil {
		t.Fatalf("man help template failed to render: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"NAME", "SYNOPSIS", "DESCRIPTION", "EXAMPLES", "OPTIONS", "SEE ALSO"} {
		if !strings.Contains(out, want) {
			t.Errorf("man help output missing %q section\n---\n%s", want, out)
		}
	}
	// The removed annotation sections must not reappear without a setter.
	for _, gone := range []string{"EXIT STATUS", "FILES", "OUTPUT"} {
		if strings.Contains(out, gone) {
			t.Errorf("unexpected %q section in man help (annotation hook was removed)", gone)
		}
	}
}
