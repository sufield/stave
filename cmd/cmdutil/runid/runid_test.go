package runid

import (
	"testing"
)

func TestGenerateRunID(t *testing.T) {
	id := GenerateRunID("hash1", "hash2")
	if id == "" {
		t.Fatal("expected non-empty run ID")
	}

	// Same inputs should produce same ID
	id2 := GenerateRunID("hash1", "hash2")
	if id != id2 {
		t.Errorf("expected deterministic: %q != %q", id, id2)
	}

	// Different inputs should produce different ID
	id3 := GenerateRunID("hash3", "hash4")
	if id == id3 {
		t.Errorf("expected different IDs for different inputs")
	}
}

func TestGenerateRunID_TrimsWhitespace(t *testing.T) {
	id1 := GenerateRunID("hash1", "hash2")
	id2 := GenerateRunID(" hash1 ", " hash2 ")
	if id1 != id2 {
		t.Errorf("expected trimmed inputs to match: %q != %q", id1, id2)
	}
}
