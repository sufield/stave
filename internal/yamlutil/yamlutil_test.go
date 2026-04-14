package yamlutil

import (
	"strings"
	"testing"
)

func TestQuote_EscapesDoubleQuote(t *testing.T) {
	got := Quote(`foo"bar`)
	if got != `"foo\"bar"` {
		t.Errorf("got %q, want %q", got, `"foo\"bar"`)
	}
}

func TestQuote_EscapesNewline(t *testing.T) {
	got := Quote("line1\nline2")
	if !strings.Contains(got, `\n`) {
		t.Errorf("expected escaped newline, got %q", got)
	}
	if strings.Contains(got, "\n") {
		t.Error("literal newline should not be present")
	}
}

func TestQuote_EscapesBackslash(t *testing.T) {
	got := Quote(`a\b`)
	if got != `"a\\b"` {
		t.Errorf("got %q, want %q", got, `"a\\b"`)
	}
}

func TestQuote_SimpleString(t *testing.T) {
	got := Quote("hello")
	if got != `"hello"` {
		t.Errorf("got %q, want %q", got, `"hello"`)
	}
}

func TestBlock_PreservesLineBreaks(t *testing.T) {
	got := Block("line1\nline2\nline3", 4)
	if !strings.HasPrefix(got, "|\n") {
		t.Error("block should start with |\\n")
	}
	if !strings.Contains(got, "    line1\n") {
		t.Error("lines should be indented")
	}
	if strings.Count(got, "\n") != 4 { // header + 3 lines
		t.Errorf("expected 4 newlines, got %d", strings.Count(got, "\n"))
	}
}

func TestBlock_PreventsStructureInjection(t *testing.T) {
	// A malicious value with YAML keys should be safely indented
	got := Block("key: value\nevil: true", 2)
	// Both lines should be indented — not at root level
	if strings.Contains(got, "\nevil:") {
		t.Error("injection should be prevented by indentation")
	}
	if !strings.Contains(got, "  evil: true") {
		t.Error("evil line should be safely indented")
	}
}
