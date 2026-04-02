package jsonutil

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriteIndented(t *testing.T) {
	var buf bytes.Buffer
	v := map[string]string{"key": "value"}
	if err := WriteIndented(&buf, v); err != nil {
		t.Fatalf("WriteIndented error: %v", err)
	}

	got := buf.String()
	// Should be indented with two spaces.
	if !strings.Contains(got, "  \"key\"") {
		t.Errorf("expected indented output, got:\n%s", got)
	}
	// Should end with a newline (json.Encoder.Encode appends one).
	if !strings.HasSuffix(got, "\n") {
		t.Error("expected trailing newline")
	}
}

func TestWriteIndented_NoHTMLEscape(t *testing.T) {
	var buf bytes.Buffer
	v := map[string]string{"html": "<b>bold</b> & stuff"}
	if err := WriteIndented(&buf, v); err != nil {
		t.Fatalf("WriteIndented error: %v", err)
	}

	got := buf.String()
	// With HTML escaping disabled, angle brackets and ampersand should be literal.
	if strings.Contains(got, `\u003c`) || strings.Contains(got, `\u0026`) {
		t.Errorf("HTML escaping should be disabled, got:\n%s", got)
	}
	if !strings.Contains(got, "<b>bold</b> & stuff") {
		t.Errorf("expected literal HTML characters, got:\n%s", got)
	}
}

func TestWriteIndented_Nil(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteIndented(&buf, nil); err != nil {
		t.Fatalf("WriteIndented(nil) error: %v", err)
	}
	got := strings.TrimSpace(buf.String())
	if got != "null" {
		t.Errorf("WriteIndented(nil) = %q, want %q", got, "null")
	}
}

func TestWriteIndented_Struct(t *testing.T) {
	type example struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	var buf bytes.Buffer
	if err := WriteIndented(&buf, example{Name: "test", Count: 42}); err != nil {
		t.Fatalf("WriteIndented error: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, `"name": "test"`) {
		t.Errorf("expected name field, got:\n%s", got)
	}
	if !strings.Contains(got, `"count": 42`) {
		t.Errorf("expected count field, got:\n%s", got)
	}
}
