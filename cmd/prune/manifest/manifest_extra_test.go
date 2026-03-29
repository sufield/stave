package manifest

import (
	"testing"
)

func TestIsManifestArtifact(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"manifest.json", true},
		{"Manifest.json", true},
		{"MANIFEST.JSON", true},
		{"signed-manifest.json", true},
		{"Signed-Manifest.json", true},
		{"custom.manifest.json", true},
		{"custom.signed-manifest.json", true},
		{"snapshot.json", false},
		{"data.json", false},
		{"manifest.yaml", false},
		{"", false},
	}
	for _, tt := range tests {
		got := isManifestArtifact(tt.name)
		if got != tt.want {
			t.Errorf("isManifestArtifact(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestGenerateConfig_Defaults(t *testing.T) {
	cfg := GenerateConfig{}
	if cfg.TextOutput {
		t.Fatal("default TextOutput should be false")
	}
	if cfg.OutPath != "" {
		t.Fatalf("default OutPath should be empty, got %q", cfg.OutPath)
	}
}

func TestKeygenConfig_Defaults(t *testing.T) {
	cfg := KeygenConfig{}
	if cfg.TextOutput {
		t.Fatal("default TextOutput should be false")
	}
}

func TestSignConfig_Defaults(t *testing.T) {
	cfg := SignConfig{}
	if cfg.TextOutput {
		t.Fatal("default TextOutput should be false")
	}
}
