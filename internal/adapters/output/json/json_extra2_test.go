package json

import (
	"bytes"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// WriteUpcomingJSON
// ---------------------------------------------------------------------------

func TestWriteUpcomingJSON_Simple(t *testing.T) {
	data := map[string]any{
		"upcoming": []map[string]any{
			{"control_id": "CTL.A.001", "asset_id": "bucket-1"},
		},
	}
	var buf bytes.Buffer
	err := WriteUpcomingJSON(&buf, data)
	if err != nil {
		t.Fatalf("WriteUpcomingJSON: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "CTL.A.001") {
		t.Error("missing control_id")
	}
}

func TestWriteUpcomingJSON_Nil(t *testing.T) {
	var buf bytes.Buffer
	err := WriteUpcomingJSON(&buf, nil)
	if err != nil {
		t.Fatalf("WriteUpcomingJSON nil: %v", err)
	}
}

// ---------------------------------------------------------------------------
// WriteValidation (renamed to avoid collision)
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
