package capabilities

import (
	"slices"
	"testing"
)

func TestSynonymsFor_CaseInsensitive(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Public", "open"},
		{"PUBLIC", "open"},
		{"KMS", "encryption"},
		{"Admin", "administrator"},
	}

	for _, tt := range tests {
		got := SynonymsFor(tt.input)
		if len(got) == 0 {
			t.Errorf("SynonymsFor(%q) returned empty slice, expected to contain %q", tt.input, tt.expected)
			continue
		}
		if !slices.Contains(got, tt.expected) {
			t.Errorf("SynonymsFor(%q) = %v; expected to contain %q", tt.input, got, tt.expected)
		}
	}
}
