package exempt

import (
	"bytes"
	"encoding/json"
	"testing"
)

// Test_RedGate_WriteListJSONSnakeCase asserts the CORRECT behavior:
// WriteList(format="json") must emit the canonical snake_case schema
// keys (control_id, rationale, acknowledged_by, acknowledged_date)
// matching controldef.AcknowledgmentRule and the Save()/YAML path, so
// that a JSON consumer of `exempt list --format json` can round-trip
// the output back into the apply --acknowledgment-file schema.
//
// store.go fields carry ONLY yaml tags and no json tags, so encoding/json
// falls back to PascalCase Go field names (ControlID, Reason, Approver,
// AcknowledgedDate). This test fails against current code.
func Test_RedGate_WriteListJSONSnakeCase(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic during WriteList JSON snake_case test: %v", r)
		}
	}()

	f := &AcceptanceFile{
		SchemaVersion: "1",
		Acknowledgments: []AcknowledgmentEntry{
			{
				ID:               "CTL.A.001@asset-1",
				ControlID:        "CTL.A.001",
				AssetID:          "asset-1",
				Reason:           "documented migration risk",
				Approver:         "alice",
				AcknowledgedDate: "2026-05-01",
				ExpiryDate:       "2026-12-31",
				Status:           AckStatusActive,
			},
		},
	}

	var buf bytes.Buffer
	if err := WriteList(&buf, f, "json", "all", true); err != nil {
		t.Fatalf("WriteList returned error: %v", err)
	}

	// Decode into a generic structure to inspect the actual emitted keys.
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("emitted JSON is not valid: %v\nraw:\n%s", err, buf.String())
	}

	acksRaw, ok := doc["acknowledgments"]
	if !ok {
		t.Fatalf("JSON output missing snake_case top-level key %q; got keys %v\nraw:\n%s",
			"acknowledgments", keysOf(doc), buf.String())
	}
	acks, ok := acksRaw.([]any)
	if !ok || len(acks) != 1 {
		t.Fatalf("acknowledgments is not a 1-element array: %#v", acksRaw)
	}
	ack, ok := acks[0].(map[string]any)
	if !ok {
		t.Fatalf("acknowledgment[0] is not an object: %#v", acks[0])
	}

	// The canonical schema keys that a YAML/apply consumer requires.
	wantKeys := []string{"control_id", "rationale", "acknowledged_by", "acknowledged_date"}
	for _, k := range wantKeys {
		if _, present := ack[k]; !present {
			t.Fatalf("acknowledgment JSON missing canonical schema key %q; got keys %v\nraw:\n%s",
				k, keysOf(ack), buf.String())
		}
	}
}

func keysOf(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}
