package cliflags

import (
	"strings"
	"testing"
	"time"
)

func TestParseRFC3339_Valid(t *testing.T) {
	got, err := ParseRFC3339("2026-01-15T00:00:00Z", "--now")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseRFC3339_ValidWithOffset(t *testing.T) {
	got, err := ParseRFC3339("2026-01-15T12:00:00+05:00", "--now")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should be converted to UTC
	if got.Location().String() != "UTC" {
		t.Fatalf("expected UTC, got %s", got.Location())
	}
}

func TestParseRFC3339_Invalid(t *testing.T) {
	_, err := ParseRFC3339("bad-time", "--now")
	if err == nil {
		t.Fatal("expected error for invalid time")
	}
	if !strings.Contains(err.Error(), "--now") {
		t.Fatalf("error should mention --now, got: %v", err)
	}
	if !strings.Contains(err.Error(), "bad-time") {
		t.Fatalf("error should contain the invalid value, got: %v", err)
	}
}

func TestWithDynamicDefaultHelp(t *testing.T) {
	base := "Some help text"
	got := WithDynamicDefaultHelp(base)
	if !strings.HasPrefix(got, base) {
		t.Fatalf("expected prefix %q, got %q", base, got)
	}
	if !strings.Contains(got, "STAVE_*") {
		t.Fatalf("expected dynamic default suffix, got: %q", got)
	}
}

func TestResolveFormat_TrimsWhitespace(t *testing.T) {
	got := ResolveFormat(nil, "  json  ")
	if got != "json" {
		t.Fatalf("got %q, want %q", got, "json")
	}
}

func TestResolveFormatPure_TrimsWhitespace(t *testing.T) {
	got := ResolveFormatPure("  text  ", false, false)
	if got != "text" {
		t.Fatalf("got %q, want %q", got, "text")
	}
}

func TestGlobalFlags_TextOutputEnabled(t *testing.T) {
	tests := []struct {
		quiet bool
		want  bool
	}{
		{false, true},
		{true, false},
	}
	for _, tt := range tests {
		gf := GlobalFlags{Quiet: tt.quiet}
		if got := gf.TextOutputEnabled(); got != tt.want {
			t.Errorf("TextOutputEnabled(quiet=%v) = %v, want %v", tt.quiet, got, tt.want)
		}
	}
}

func TestGlobalFlags_GetSanitizer(t *testing.T) {
	gf := GlobalFlags{Sanitize: true}
	s := gf.GetSanitizer()
	if s == nil {
		t.Fatal("expected non-nil sanitizer")
	}
}

func TestGlobalFlags_GetSanitizer_Default(t *testing.T) {
	gf := GlobalFlags{}
	s := gf.GetSanitizer()
	if s == nil {
		t.Fatal("expected non-nil sanitizer")
	}
}

func TestGetGlobalFlags_NilCmd(t *testing.T) {
	gf := GetGlobalFlags(nil)
	if gf.Quiet || gf.Force || gf.Sanitize {
		t.Fatalf("expected all-false flags for nil cmd, got: %+v", gf)
	}
}

func TestDefaultControlsDir(t *testing.T) {
	if DefaultControlsDir == "" {
		t.Fatal("DefaultControlsDir should not be empty")
	}
}

func TestFormatsTextJSON(t *testing.T) {
	if len(FormatsTextJSON) != 2 {
		t.Fatalf("FormatsTextJSON len = %d, want 2", len(FormatsTextJSON))
	}
}

func TestFormatsTextJSONSARIF(t *testing.T) {
	if len(FormatsTextJSONSARIF) != 3 {
		t.Fatalf("FormatsTextJSONSARIF len = %d, want 3", len(FormatsTextJSONSARIF))
	}
}

func TestFormatsMarkdownJSON(t *testing.T) {
	if len(FormatsMarkdownJSON) != 2 {
		t.Fatalf("FormatsMarkdownJSON len = %d, want 2", len(FormatsMarkdownJSON))
	}
}
