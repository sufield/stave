package cmdutil

import (
	"testing"

	"github.com/sufield/stave/internal/sanitize"
)

func TestParsePathMode(t *testing.T) {
	tests := []struct {
		input string
		want  sanitize.PathMode
	}{
		{"base", sanitize.PathBase},
		{"full", sanitize.PathFull},
		{" FULL ", sanitize.PathFull},
		{"", sanitize.PathBase},
		{"other", sanitize.PathBase},
	}
	for _, tt := range tests {
		got := ParsePathMode(tt.input)
		if got != tt.want {
			t.Errorf("ParsePathMode(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
