package json

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriteValidation(t *testing.T) {
	var buf bytes.Buffer
	report := map[string]any{"valid": true, "errors": []string{}}
	err := WriteValidation(&buf, report)
	if err != nil {
		t.Fatalf("WriteValidation() error = %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `"valid"`) {
		t.Fatalf("unexpected output: %s", out)
	}
}
