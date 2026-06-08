package cliapi

import (
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/sir"
	"github.com/sufield/stave/internal/core/sirfacts"
)

// These exercise the SIR renderers that moved here from cmd/exportsir.

func TestRenderSIR_JSONNonEmpty(t *testing.T) {
	out, err := renderSIR(&sir.Document{}, nil, false, "json")
	if err != nil {
		t.Fatalf("renderSIR json: %v", err)
	}
	if len(out) == 0 {
		t.Error("renderSIR json produced empty output")
	}
}

func TestRenderSIR_FactStreamsNoError(t *testing.T) {
	for _, format := range []string{"jsonl", "smt2"} {
		if _, err := renderSIR(&sir.Document{}, []sirfacts.Fact{}, false, format); err != nil {
			t.Errorf("renderSIR(%q): unexpected error: %v", format, err)
		}
	}
}

func TestRenderSIR_UnknownFormatErrors(t *testing.T) {
	_, err := renderSIR(&sir.Document{}, nil, false, "yaml")
	if err == nil {
		t.Fatal("expected error for unknown format")
	}
	if !strings.Contains(err.Error(), "--format must be one of") {
		t.Errorf("error should explain format, got: %q", err.Error())
	}
}
