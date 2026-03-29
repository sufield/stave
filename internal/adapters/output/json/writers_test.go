package json

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriteUpcomingJSON(t *testing.T) {
	var buf bytes.Buffer
	data := map[string]any{"key": "value", "count": 42}
	err := WriteUpcomingJSON(&buf, data)
	if err != nil {
		t.Fatalf("WriteUpcomingJSON() error = %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `"key"`) || !strings.Contains(out, `"value"`) {
		t.Fatalf("unexpected output: %s", out)
	}
}

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

func TestWriteReadinessJSON(t *testing.T) {
	var buf bytes.Buffer
	report := struct {
		Ready bool `json:"ready"`
	}{Ready: true}
	err := WriteReadinessJSON(&buf, report)
	if err != nil {
		t.Fatalf("WriteReadinessJSON() error = %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `"ready"`) {
		t.Fatalf("unexpected output: %s", out)
	}
}
