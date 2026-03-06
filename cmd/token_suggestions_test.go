package cmd

import (
	"strings"
	"testing"

	"github.com/sufield/stave/cmd/enforce/generate"
	"github.com/sufield/stave/internal/cli/ui"
)

func TestParseOutputFormat_IsCaseInsensitive(t *testing.T) {
	got, err := ui.ParseOutputFormat("JSON")
	if err != nil {
		t.Fatalf("ParseOutputFormat returned error: %v", err)
	}
	if got != ui.OutputFormatJSON {
		t.Fatalf("ParseOutputFormat(JSON)=%q, want %q", got, ui.OutputFormatJSON)
	}
}

func TestParseOutputFormat_SuggestsClosestValue(t *testing.T) {
	_, err := ui.ParseOutputFormat("jsn")
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
	if !strings.Contains(err.Error(), `Did you mean "json"?`) {
		t.Fatalf("expected suggestion, got: %v", err)
	}
}

func TestParseEnforceMode_IsCaseInsensitive(t *testing.T) {
	got, err := generate.ParseMode("SCP")
	if err != nil {
		t.Fatalf("ParseMode returned error: %v", err)
	}
	if got != generate.ModeSCP {
		t.Fatalf("ParseMode(SCP)=%q, want %q", got, generate.ModeSCP)
	}
}

func TestParseEnforceMode_SuggestsClosestValue(t *testing.T) {
	_, err := generate.ParseMode("pac")
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
	if !strings.Contains(err.Error(), `Did you mean "pab"?`) {
		t.Fatalf("expected suggestion, got: %v", err)
	}
}
