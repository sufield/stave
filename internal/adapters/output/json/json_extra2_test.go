package json

import (
	"bytes"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// WriteValidation
// ---------------------------------------------------------------------------

func TestWriteValidation_MapInput(t *testing.T) {
	report := map[string]any{
		"issues": []string{"single snapshot"},
	}
	var buf bytes.Buffer
	err := WriteValidation(&buf, report)
	if err != nil {
		t.Fatalf("WriteValidation: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "single snapshot") {
		t.Error("missing issue")
	}
}

// ---------------------------------------------------------------------------
