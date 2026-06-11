package netutil_test

import (
	"testing"

	"github.com/sufield/stave/internal/platform/netutil"
)

func TestEscapeFragment_PreservesSlash(t *testing.T) {
	got := netutil.EscapeFragment("guides/getting-started")
	want := "guides/getting-started"
	if got != want {
		t.Errorf("EscapeFragment() = %q, want %q", got, want)
	}
}

func TestEscapeFragment_EscapesSpaceAsPercent20(t *testing.T) {
	got := netutil.EscapeFragment("guides/getting started")
	want := "guides/getting%20started"
	if got != want {
		t.Errorf("EscapeFragment() = %q, want %q: spaces in fragments must be escaped as %%20 (not +) for standard browser anchor routing", got, want)
	}
}
