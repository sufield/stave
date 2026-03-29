package projconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolver_NearestFile_Found(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "stave.yaml")
	if err := os.WriteFile(configFile, []byte("project: test"), 0o600); err != nil {
		t.Fatal(err)
	}

	r := &Resolver{WorkingDir: dir, HomeDir: t.TempDir()}
	path, ok := r.NearestFile("stave.yaml")
	if !ok {
		t.Fatal("expected to find stave.yaml")
	}
	if path != configFile {
		t.Fatalf("path = %q, want %q", path, configFile)
	}
}

func TestResolver_NearestFile_NotFound(t *testing.T) {
	r := &Resolver{WorkingDir: t.TempDir(), HomeDir: t.TempDir()}
	_, ok := r.NearestFile("nonexistent.yaml")
	if ok {
		t.Fatal("expected not to find nonexistent file")
	}
}

func TestResolver_NearestFile_Ancestry(t *testing.T) {
	root := t.TempDir()
	configFile := filepath.Join(root, "stave.yaml")
	if err := os.WriteFile(configFile, []byte("project: test"), 0o600); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}

	r := &Resolver{WorkingDir: nested, HomeDir: t.TempDir()}
	path, ok := r.NearestFile("stave.yaml")
	if !ok {
		t.Fatal("expected to find stave.yaml via ancestry")
	}
	if path != configFile {
		t.Fatalf("path = %q", path)
	}
}

func TestResolver_LoadProjectConfig_Valid(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "stave.yaml")
	if err := os.WriteFile(configFile, []byte("max_unsafe_duration: 24h\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	r := &Resolver{WorkingDir: dir, HomeDir: t.TempDir()}
	cfg, err := r.loadProjectConfig(configFile)
	if err != nil {
		t.Fatalf("loadProjectConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
}

func TestResolver_LoadProjectConfig_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "stave.yaml")
	if err := os.WriteFile(configFile, []byte("{{invalid yaml"), 0o600); err != nil {
		t.Fatal(err)
	}

	r := &Resolver{WorkingDir: dir, HomeDir: t.TempDir()}
	_, err := r.loadProjectConfig(configFile)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestResolver_FindProjectConfig_ContextPath(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "custom.yaml")
	if err := os.WriteFile(configFile, []byte("max_unsafe_duration: 48h\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	r := &Resolver{WorkingDir: t.TempDir(), HomeDir: t.TempDir()}
	cfg, path, err := r.FindProjectConfig(configFile)
	if err != nil {
		t.Fatalf("FindProjectConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if path != configFile {
		t.Fatalf("path = %q", path)
	}
}

func TestResolver_FindProjectConfig_ContextPath_Missing(t *testing.T) {
	r := &Resolver{WorkingDir: t.TempDir(), HomeDir: t.TempDir()}
	_, _, err := r.FindProjectConfig("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing context path")
	}
}

func TestResolver_UserConfigPath_NoOverride(t *testing.T) {
	r := &Resolver{HomeDir: "/home/testuser"}
	path, err := r.UserConfigPath()
	if err != nil {
		t.Fatalf("UserConfigPath: %v", err)
	}
	expected := "/home/testuser/.config/stave/config.yaml"
	if path != expected {
		t.Fatalf("path = %q, want %q", path, expected)
	}
}

func TestResolver_UserConfigPath_EmptyHome(t *testing.T) {
	r := &Resolver{HomeDir: ""}
	_, err := r.UserConfigPath()
	if err == nil {
		t.Fatal("expected error for empty home")
	}
}

func TestBuildEvaluator_AlwaysReturnsEvaluator(t *testing.T) {
	result := BuildEvaluator()
	if result.Evaluator == nil {
		t.Fatal("Evaluator should never be nil")
	}
}
