package yamlutil

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
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

// TestQuote_EscapesC0Controls pins that every C0 control character
// (NUL, BEL, ESC, DEL) is escaped via \xNN. Earlier shape passed
// these through verbatim and produced YAML that yaml.v3 refused to
// re-parse.
func TestQuote_EscapesC0Controls(t *testing.T) {
	cases := map[string]string{
		"NUL": "\x00",
		"BEL": "\x07",
		"ESC": "\x1b",
		"DEL": "\x7f",
	}
	for name, ch := range cases {
		got := Quote("a" + ch + "b")
		if strings.ContainsRune(got, rune(ch[0])) {
			t.Errorf("%s: literal control char survived in %q", name, got)
		}
	}
}

// TestQuote_EscapesC1Controls pins that the C1 control range
// (U+0080 through U+009F) is also escaped. yaml.v3 rejects literal
// C1 controls on parse, so a serializer that emitted them produced
// output its own re-parser refused.
func TestQuote_EscapesC1Controls(t *testing.T) {
	cases := map[string]rune{
		"PAD (U+0080)": 0x0080,
		"NEL (U+0085)": 0x0085,
		"CSI (U+009B)": 0x009b,
		"APC (U+009F)": 0x009f,
	}
	for name, r := range cases {
		got := Quote("a" + string(r) + "b")
		if strings.ContainsRune(got, r) {
			t.Errorf("%s: literal C1 control survived in %q", name, got)
		}
		want := "\\u" + map[rune]string{
			0x0080: "0080",
			0x0085: "0085",
			0x009b: "009b",
			0x009f: "009f",
		}[r]
		if !strings.Contains(got, want) {
			t.Errorf("%s: expected %q in %q", name, want, got)
		}
	}
}

// TestQuote_RoundTripsThroughYAMLParser pins that what we emit, the
// downstream YAML parser can read back. A serializer that produces
// output its own re-parser rejects is broken.
func TestQuote_RoundTripsThroughYAMLParser(t *testing.T) {
	inputs := []string{
		"plain",
		"with \"quotes\"",
		"newline\nhere",
		"tab\there",
		"escaped\x07bell",
		"esc\x1bsequence",
		"null\x00middle",
	}
	for _, in := range inputs {
		quoted := Quote(in)
		var got string
		if err := yaml.Unmarshal([]byte(quoted), &got); err != nil {
			t.Errorf("yaml.Unmarshal(%q): %v", quoted, err)
			continue
		}
		if got != in {
			t.Errorf("round-trip mismatch: input=%q quoted=%q got=%q", in, quoted, got)
		}
	}
}

func TestBlock_EmptyString(t *testing.T) {
	if got := Block("", 2); got != `""` {
		t.Errorf("Block(\"\") = %q, want \"\\\"\\\"\"", got)
	}
}

func TestBlock_NormalizesCRLF(t *testing.T) {
	got := Block("line1\r\nline2\r\nline3", 0)
	if strings.Contains(got, "\r") {
		t.Errorf("CRLF should be normalized; got %q", got)
	}
	want := "|\nline1\nline2\nline3\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
