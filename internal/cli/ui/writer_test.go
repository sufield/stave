package ui

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"
)

func TestNewWriter(t *testing.T) {
	w := NewWriter(nil, nil, OutputFormatJSON, true)
	if w.Mode() != OutputFormatJSON {
		t.Errorf("expected mode JSON, got %v", w.Mode())
	}
	if !w.IsJSON() {
		t.Error("expected IsJSON() to return true")
	}
}

func TestWriter_Stdout_QuietModeText(t *testing.T) {
	var stdout, stderr bytes.Buffer
	w := NewWriter(&stdout, &stderr, OutputFormatText, true)

	// In text+quiet mode, stdout should be discarded
	out := w.Stdout()
	if out != io.Discard {
		t.Error("expected stdout to be io.Discard in quiet+text mode")
	}
}

func TestWriter_Stdout_QuietModeJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	w := NewWriter(&stdout, &stderr, OutputFormatJSON, true)

	// In JSON mode, stdout should NOT be discarded (JSON always goes to stdout)
	out := w.Stdout()
	if out == io.Discard {
		t.Error("expected stdout NOT to be io.Discard in JSON mode")
	}
}

func TestWriter_Stderr_QuietMode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	w := NewWriter(&stdout, &stderr, OutputFormatJSON, true)

	// In quiet mode, stderr should be discarded
	out := w.Stderr()
	if out != io.Discard {
		t.Error("expected stderr to be io.Discard in quiet mode")
	}
}

func TestWriter_WriteJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	w := NewWriter(&stdout, &stderr, OutputFormatJSON, false)

	data := map[string]string{"key": "value"}
	err := w.WriteJSON(data)
	if err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}

	// Parse the output
	var result Envelope
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	if !result.OK {
		t.Error("expected ok=true in envelope")
	}
	if result.Data == nil {
		t.Error("expected data in envelope")
	}
}

func TestWriter_WriteJSONRaw(t *testing.T) {
	var stdout, stderr bytes.Buffer
	w := NewWriter(&stdout, &stderr, OutputFormatJSON, false)

	data := map[string]string{"key": "value"}
	err := w.WriteJSONRaw(data)
	if err != nil {
		t.Fatalf("WriteJSONRaw failed: %v", err)
	}

	// Parse the output - should NOT have envelope
	var result map[string]string
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	if result["key"] != "value" {
		t.Errorf("expected key=value, got %v", result)
	}
}

func TestWriter_Info_QuietMode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	w := NewWriter(&stdout, &stderr, OutputFormatText, true)

	w.Info("hello")

	if got := stderr.String(); got != "" {
		t.Fatalf("expected no stderr output in quiet mode, got %q", got)
	}
}

func TestWriter_Info_WritesToStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	w := NewWriter(&stdout, &stderr, OutputFormatText, false)
	forceTTY := false
	w.rt.IsTTY = &forceTTY

	w.Info("hello")

	got := stderr.String()
	if got == "" {
		t.Fatal("expected stderr output")
	}
	if !bytes.Contains([]byte(got), []byte("[INFO] hello")) {
		t.Fatalf("expected info message, got %q", got)
	}
}
