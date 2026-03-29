package projctx

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolver_IsProjectRoot_WithSession(t *testing.T) {
	dir := t.TempDir()
	sessionDir := filepath.Join(dir, ".stave")
	if err := os.MkdirAll(sessionDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sessionDir, "session.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	r := &Resolver{WorkingDir: dir}
	if !r.IsProjectRoot(dir) {
		t.Fatal("expected project root with session file")
	}
}

func TestResolver_IsProjectRoot_WithDirs(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "controls"), 0o755)
	os.MkdirAll(filepath.Join(dir, "observations"), 0o755)

	r := &Resolver{WorkingDir: dir}
	if !r.IsProjectRoot(dir) {
		t.Fatal("expected project root with controls+observations dirs")
	}
}

func TestResolver_IsProjectRoot_NotProject(t *testing.T) {
	r := &Resolver{WorkingDir: t.TempDir()}
	if r.IsProjectRoot(t.TempDir()) {
		t.Fatal("empty dir should not be project root")
	}
}

func TestResolver_DetectProjectRoot_Found(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "controls"), 0o755)
	os.MkdirAll(filepath.Join(root, "observations"), 0o755)
	nested := filepath.Join(root, "deep", "nested")
	os.MkdirAll(nested, 0o755)

	r := &Resolver{WorkingDir: nested}
	found, err := r.DetectProjectRoot(nested)
	if err != nil {
		t.Fatalf("DetectProjectRoot: %v", err)
	}
	if found != root {
		t.Fatalf("found = %q, want %q", found, root)
	}
}

func TestResolver_DetectProjectRoot_NotFound(t *testing.T) {
	r := &Resolver{WorkingDir: t.TempDir()}
	_, err := r.DetectProjectRoot(t.TempDir())
	if err == nil {
		t.Fatal("expected error for non-project dir")
	}
}

func TestSaveAndLoadSession(t *testing.T) {
	dir := t.TempDir()
	if err := SaveSession(dir, []string{"apply", "--controls", "s3"}); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	st, err := LoadSession(dir)
	if err != nil {
		t.Fatalf("LoadSession: %v", err)
	}
	if st == nil {
		t.Fatal("expected non-nil session")
	}
	if st.LastCommand != "apply --controls s3" {
		t.Fatalf("LastCommand = %q", st.LastCommand)
	}
}

func TestSaveSession_EmptyRoot(t *testing.T) {
	if err := SaveSession("", []string{"apply"}); err != nil {
		t.Fatal("empty root should return nil")
	}
}

func TestSaveSession_EmptyArgs(t *testing.T) {
	if err := SaveSession("/tmp", nil); err != nil {
		t.Fatal("empty args should return nil")
	}
}

func TestLoadSession_NoFile(t *testing.T) {
	st, err := LoadSession(t.TempDir())
	if err != nil {
		t.Fatalf("LoadSession error: %v", err)
	}
	if st != nil {
		t.Fatal("expected nil for missing session")
	}
}

func TestLoadSession_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	sessionDir := filepath.Join(dir, ".stave")
	os.MkdirAll(sessionDir, 0o755)
	os.WriteFile(filepath.Join(sessionDir, "session.json"), []byte(`{invalid`), 0o600)

	_, err := LoadSession(dir)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestInferenceLog_Explain_NoError(t *testing.T) {
	log := &InferenceLog{attempts: map[string]InferAttempt{
		"controls": {FlagName: "controls", Resolved: "/path/to/controls"},
	}}
	if got := log.Explain("controls"); got != "" {
		t.Fatalf("expected empty for no error, got %q", got)
	}
}

func TestInferenceLog_Explain_WithError(t *testing.T) {
	log := &InferenceLog{attempts: map[string]InferAttempt{
		"controls": {FlagName: "controls", Error: "not found", Searched: "cwd"},
	}}
	got := log.Explain("controls")
	if got == "" {
		t.Fatal("expected non-empty explanation")
	}
}

func TestInferenceLog_Explain_NilLog(t *testing.T) {
	var log *InferenceLog
	if got := log.Explain("controls"); got != "" {
		t.Fatalf("expected empty for nil log, got %q", got)
	}
}

func TestInferenceLog_Explain_Missing(t *testing.T) {
	log := &InferenceLog{attempts: map[string]InferAttempt{}}
	if got := log.Explain("controls"); got != "" {
		t.Fatalf("expected empty for missing key, got %q", got)
	}
}

func TestInferenceEngine_InferDir_NonEmpty(t *testing.T) {
	r := &Resolver{WorkingDir: t.TempDir()}
	engine := NewInferenceEngine(r)
	// Non-empty input should be returned as-is
	if got := engine.InferDir("controls", "/my/controls"); got != "/my/controls" {
		t.Fatalf("got %q", got)
	}
}
