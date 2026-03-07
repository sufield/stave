package kernel

import (
	"encoding/json"
	"testing"
)

func FuzzNewControlID(f *testing.F) {
	seeds := []string{
		"",
		"CTL.S3.PUBLIC.001",
		"CTL.S3.PUBLIC.LIST.001",
		"CTL.S3.ACL.ESCALATION.001",
		"INV.S3.PUBLIC.001",
		"FOO",
		"...",
		"CTL.",
		"CTL.S3.PUBLIC",
		"CTL.S3.PUBLIC.1",
		"CTL.S3.PUBLIC.0001",
		string(make([]byte, 1024)),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		id, err := NewControlID(input)
		if err == nil {
			// Valid ID must survive JSON round-trip.
			data, err := json.Marshal(id)
			if err != nil {
				t.Fatalf("Marshal valid ControlID %q: %v", id, err)
			}
			var rt ControlID
			if err := json.Unmarshal(data, &rt); err != nil {
				t.Fatalf("Unmarshal valid ControlID %q: %v", string(data), err)
			}
			if rt != id {
				t.Fatalf("round-trip mismatch: got %q, want %q", rt, id)
			}
		}
	})
}
