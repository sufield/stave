package predicate

import (
	"encoding/json"
	"testing"
)

func TestNewFieldPath(t *testing.T) {
	tests := []struct {
		input    string
		wantStr  string
		wantZero bool
		wantLen  int
	}{
		{"", "", true, 0},
		{"name", "name", false, 1},
		{"a.b.c", "a.b.c", false, 3},
		{"properties.storage.access.public_read", "properties.storage.access.public_read", false, 4},
	}
	for _, tt := range tests {
		fp := NewFieldPath(tt.input)
		if fp.String() != tt.wantStr {
			t.Errorf("NewFieldPath(%q).String() = %q, want %q", tt.input, fp.String(), tt.wantStr)
		}
		if fp.IsZero() != tt.wantZero {
			t.Errorf("NewFieldPath(%q).IsZero() = %v, want %v", tt.input, fp.IsZero(), tt.wantZero)
		}
		if len(fp.Parts()) != tt.wantLen {
			t.Errorf("NewFieldPath(%q).Parts() has %d parts, want %d", tt.input, len(fp.Parts()), tt.wantLen)
		}
	}
}

func TestFieldPath_Parts(t *testing.T) {
	fp := NewFieldPath("a.b.c")
	parts := fp.Parts()
	want := []string{"a", "b", "c"}
	if len(parts) != len(want) {
		t.Fatalf("Parts() length = %d, want %d", len(parts), len(want))
	}
	for i, p := range parts {
		if p != want[i] {
			t.Errorf("Parts()[%d] = %q, want %q", i, p, want[i])
		}
	}
}

func TestFieldPath_TrimPrefix(t *testing.T) {
	tests := []struct {
		path   string
		prefix string
		want   string
	}{
		{"properties.name", "properties.", "name"},
		{"properties.name", "other.", "properties.name"},
		{"abc", "", "abc"},
		{"", "x", ""},
	}
	for _, tt := range tests {
		fp := NewFieldPath(tt.path)
		if got := fp.TrimPrefix(tt.prefix); got != tt.want {
			t.Errorf("NewFieldPath(%q).TrimPrefix(%q) = %q, want %q", tt.path, tt.prefix, got, tt.want)
		}
	}
}

func TestFieldPath_JSON(t *testing.T) {
	fp := NewFieldPath("a.b.c")
	data, err := json.Marshal(fp)
	if err != nil {
		t.Fatalf("MarshalJSON error: %v", err)
	}
	if string(data) != `"a.b.c"` {
		t.Errorf("MarshalJSON = %s, want %q", data, "a.b.c")
	}

	var fp2 FieldPath
	if err := json.Unmarshal(data, &fp2); err != nil {
		t.Fatalf("UnmarshalJSON error: %v", err)
	}
	if fp2.String() != "a.b.c" {
		t.Errorf("after unmarshal String() = %q, want %q", fp2.String(), "a.b.c")
	}
	if len(fp2.Parts()) != 3 {
		t.Errorf("after unmarshal Parts() length = %d, want 3", len(fp2.Parts()))
	}
}

func TestFieldPath_UnmarshalJSON_Error(t *testing.T) {
	var fp FieldPath
	if err := json.Unmarshal([]byte(`123`), &fp); err == nil {
		t.Error("expected error unmarshaling non-string JSON, got nil")
	}
}
