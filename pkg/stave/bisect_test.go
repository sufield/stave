package stave

import (
	"strings"
	"testing"

	appbisect "github.com/sufield/stave/internal/app/bisect"
)

// These exercise the bisect renderers that moved here from cmd/bisect.

func TestRenderBisect_Formats(t *testing.T) {
	// Zero-value result: no violation window, so both formats emit output
	// and text reports no violations (json never gates exit 3).
	result := appbisect.Result{}
	for _, format := range []string{"json", "text", ""} {
		out, err := renderBisect(result, format)
		if err != nil {
			t.Fatalf("renderBisect(%q): unexpected error: %v", format, err)
		}
		if len(out.Stdout) == 0 {
			t.Errorf("renderBisect(%q): produced empty stdout", format)
		}
		if out.HasViolations {
			t.Errorf("renderBisect(%q): zero result should not report violations", format)
		}
	}
}

func TestRenderBisect_JSONNeverGatesExit3(t *testing.T) {
	// Even a JSON render of a result is reported with HasViolations=false,
	// preserving the prior behaviour where only text mode gated exit 3.
	out, err := renderBisect(appbisect.Result{}, "json")
	if err != nil {
		t.Fatalf("renderBisect json: %v", err)
	}
	if out.HasViolations {
		t.Error("json render must never set HasViolations")
	}
}

func TestRenderBisect_UnknownFormat(t *testing.T) {
	_, err := renderBisect(appbisect.Result{}, "xml")
	if err == nil {
		t.Fatal("expected error for unknown format")
	}
	if !strings.Contains(err.Error(), "unknown format") {
		t.Errorf("error should mention \"unknown format\", got: %q", err.Error())
	}
}

func TestParseBisectMode(t *testing.T) {
	for _, mode := range []string{"bisect", "scan"} {
		if _, err := parseBisectMode(mode); err != nil {
			t.Errorf("parseBisectMode(%q): %v", mode, err)
		}
	}
	if _, err := parseBisectMode("nope"); err == nil {
		t.Error("invalid mode should error")
	}
}
