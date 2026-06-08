package stave

import (
	"strings"
	"testing"

	"github.com/sufield/stave/internal/app/attackpath"
)

// TestRenderAttackPath covers the attack-path renderers that moved here
// from cmd/path: all three formats must produce non-empty output for an
// empty graph, and an unknown (or empty) format must error.
func TestRenderAttackPath(t *testing.T) {
	g := &attackpath.Graph{}
	for _, format := range []string{"json", "dot", "csv-edges"} {
		out, err := renderAttackPath(g, format)
		if err != nil {
			t.Fatalf("renderAttackPath(%q): unexpected error: %v", format, err)
		}
		if len(out) == 0 {
			t.Errorf("renderAttackPath(%q): produced empty output", format)
		}
	}
}

func TestRenderAttackPath_UnknownAndEmptyError(t *testing.T) {
	for _, format := range []string{"", "xml", "text"} {
		if _, err := renderAttackPath(&attackpath.Graph{}, format); err == nil {
			t.Errorf("renderAttackPath(%q): want error, got nil", format)
		} else if !strings.Contains(err.Error(), "unknown format") {
			t.Errorf("renderAttackPath(%q): error should mention \"unknown format\", got: %q", format, err.Error())
		}
	}
}
