package apply

import "testing"

func TestResolveContextName(t *testing.T) {
	tests := []struct {
		name     string
		root     string
		selected string
		expected string
	}{
		{"explicit context", "/path/to/project", "my-ctx", "my-ctx"},
		{"from root", "/path/to/project", "", "project"},
		{"empty root", "", "", "default"},
		{"dot root", ".", "", "default"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveContextName(tt.root, tt.selected)
			if got != tt.expected {
				t.Fatalf("ResolveContextName(%q, %q) = %q, want %q", tt.root, tt.selected, got, tt.expected)
			}
		})
	}
}
