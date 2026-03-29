package ui

import (
	"bytes"
	"strings"
	"testing"
)

func TestRenderJSON(t *testing.T) {
	var buf bytes.Buffer
	err := RenderJSON(&buf, map[string]string{"key": "value"})
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	if !strings.Contains(buf.String(), `"key"`) {
		t.Error("missing key in JSON output")
	}
}

func TestRenderText(t *testing.T) {
	var buf bytes.Buffer
	err := RenderText(&buf, "hello %s", "world")
	if err != nil {
		t.Fatalf("RenderText: %v", err)
	}
	if buf.String() != "hello world" {
		t.Fatalf("got %q", buf.String())
	}
}
