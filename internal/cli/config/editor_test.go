package config

import (
	"bytes"
	"errors"
	"testing"
)

// stubConfig is a minimal config type for testing the generic Editor.
type stubConfig struct {
	Values map[string]string
}

// stubSetStore implements SetStore[stubConfig] for testing.
type stubSetStore struct {
	cfg         *stubConfig
	path        string
	loadErr     error
	setErr      error
	writeErr    error
	writeCalled bool
}

func (s *stubSetStore) LoadOrCreate() (*stubConfig, string, error) {
	if s.loadErr != nil {
		return nil, "", s.loadErr
	}
	if s.cfg == nil {
		s.cfg = &stubConfig{Values: make(map[string]string)}
	}
	return s.cfg, s.path, nil
}

func (s *stubSetStore) CurrentValue(cfg *stubConfig, key, path string) (string, bool) {
	v, ok := cfg.Values[key]
	return v, ok
}

func (s *stubSetStore) Set(cfg *stubConfig, key, value string) error {
	if s.setErr != nil {
		return s.setErr
	}
	cfg.Values[key] = value
	return nil
}

func (s *stubSetStore) Write(path string, cfg *stubConfig) error {
	s.writeCalled = true
	return s.writeErr
}

// stubDeleteStore implements DeleteStore[stubConfig] for testing.
type stubDeleteStore struct {
	cfg         *stubConfig
	path        string
	exists      bool
	deleteErr   error
	writeErr    error
	writeCalled bool
}

func (s *stubDeleteStore) Find() (*stubConfig, string, bool) {
	return s.cfg, s.path, s.exists
}

func (s *stubDeleteStore) Delete(cfg *stubConfig, key string) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	delete(cfg.Values, key)
	return nil
}

func (s *stubDeleteStore) Write(path string, cfg *stubConfig) error {
	s.writeCalled = true
	return s.writeErr
}

func TestEditor_Set_Force(t *testing.T) {
	store := &stubSetStore{
		cfg:  &stubConfig{Values: map[string]string{"key": "old"}},
		path: "/tmp/test.yaml",
	}
	editor := &Editor[stubConfig]{
		SetStore: store,
		Stderr:   &bytes.Buffer{},
		Force:    true,
		IsTTY:    func() bool { return true },
		Confirm:  func(string) bool { return false },
	}

	result, err := editor.Set("key", "new")
	if err != nil {
		t.Fatalf("Set error: %v", err)
	}
	if !result.Applied {
		t.Error("expected Applied=true with Force=true")
	}
	if result.Key != "key" || result.Value != "new" || result.Path != "/tmp/test.yaml" {
		t.Errorf("unexpected result: %+v", result)
	}
	if !store.writeCalled {
		t.Error("expected Write to be called")
	}
}

func TestEditor_Set_NotTTY(t *testing.T) {
	store := &stubSetStore{
		cfg:  &stubConfig{Values: make(map[string]string)},
		path: "/tmp/test.yaml",
	}
	editor := &Editor[stubConfig]{
		SetStore: store,
		Stderr:   &bytes.Buffer{},
		Force:    false,
		IsTTY:    func() bool { return false },
		Confirm:  func(string) bool { return false },
	}

	result, err := editor.Set("newkey", "newval")
	if err != nil {
		t.Fatalf("Set error: %v", err)
	}
	if !result.Applied {
		t.Error("expected Applied=true when not TTY (auto-confirm)")
	}
}

func TestEditor_Set_TTY_Confirmed(t *testing.T) {
	store := &stubSetStore{
		cfg:  &stubConfig{Values: map[string]string{"key": "old"}},
		path: "/tmp/test.yaml",
	}
	var stderr bytes.Buffer
	editor := &Editor[stubConfig]{
		SetStore: store,
		Stderr:   &stderr,
		Force:    false,
		IsTTY:    func() bool { return true },
		Confirm:  func(string) bool { return true },
	}

	result, err := editor.Set("key", "new")
	if err != nil {
		t.Fatalf("Set error: %v", err)
	}
	if !result.Applied {
		t.Error("expected Applied=true when user confirms")
	}
}

func TestEditor_Set_TTY_Rejected(t *testing.T) {
	store := &stubSetStore{
		cfg:  &stubConfig{Values: map[string]string{"key": "old"}},
		path: "/tmp/test.yaml",
	}
	var stderr bytes.Buffer
	editor := &Editor[stubConfig]{
		SetStore: store,
		Stderr:   &stderr,
		Force:    false,
		IsTTY:    func() bool { return true },
		Confirm:  func(string) bool { return false },
	}

	result, err := editor.Set("key", "new")
	if err != nil {
		t.Fatalf("Set error: %v", err)
	}
	if result.Applied {
		t.Error("expected Applied=false when user rejects")
	}
	if store.writeCalled {
		t.Error("Write should NOT have been called since user rejected")
	}
}

func TestEditor_Set_LoadError(t *testing.T) {
	store := &stubSetStore{loadErr: errors.New("load failed")}
	editor := &Editor[stubConfig]{
		SetStore: store,
		Force:    true,
		IsTTY:    func() bool { return false },
	}

	_, err := editor.Set("key", "val")
	if err == nil {
		t.Fatal("expected error from LoadOrCreate")
	}
}

func TestEditor_Set_SetError(t *testing.T) {
	store := &stubSetStore{
		cfg:    &stubConfig{Values: make(map[string]string)},
		path:   "/tmp/test.yaml",
		setErr: errors.New("set failed"),
	}
	editor := &Editor[stubConfig]{
		SetStore: store,
		Force:    true,
		IsTTY:    func() bool { return false },
	}

	_, err := editor.Set("key", "val")
	if err == nil {
		t.Fatal("expected error from Set")
	}
}

func TestEditor_Set_WriteError(t *testing.T) {
	store := &stubSetStore{
		cfg:      &stubConfig{Values: make(map[string]string)},
		path:     "/tmp/test.yaml",
		writeErr: errors.New("write failed"),
	}
	editor := &Editor[stubConfig]{
		SetStore: store,
		Force:    true,
		IsTTY:    func() bool { return false },
	}

	_, err := editor.Set("key", "val")
	if err == nil {
		t.Fatal("expected error from Write")
	}
}

func TestEditor_Delete_Force(t *testing.T) {
	store := &stubDeleteStore{
		cfg:    &stubConfig{Values: map[string]string{"key": "val"}},
		path:   "/tmp/test.yaml",
		exists: true,
	}
	editor := &Editor[stubConfig]{
		DeleteStore: store,
		Stderr:      &bytes.Buffer{},
		Force:       true,
		IsTTY:       func() bool { return true },
		Confirm:     func(string) bool { return false },
	}

	result, err := editor.Delete("key")
	if err != nil {
		t.Fatalf("Delete error: %v", err)
	}
	if !result.Applied {
		t.Error("expected Applied=true with Force=true")
	}
	if store.writeCalled != true {
		t.Error("expected Write to be called")
	}
}

func TestEditor_Delete_NoConfigFile(t *testing.T) {
	store := &stubDeleteStore{exists: false}
	editor := &Editor[stubConfig]{
		DeleteStore: store,
		Force:       true,
		IsTTY:       func() bool { return false },
	}

	_, err := editor.Delete("key")
	if err == nil {
		t.Fatal("expected error when config file doesn't exist")
	}
}

func TestEditor_Delete_DeleteError(t *testing.T) {
	store := &stubDeleteStore{
		cfg:       &stubConfig{Values: map[string]string{"key": "val"}},
		path:      "/tmp/test.yaml",
		exists:    true,
		deleteErr: errors.New("delete failed"),
	}
	editor := &Editor[stubConfig]{
		DeleteStore: store,
		Force:       true,
		IsTTY:       func() bool { return false },
	}

	_, err := editor.Delete("key")
	if err == nil {
		t.Fatal("expected error from Delete")
	}
}

func TestEditor_Delete_WriteError(t *testing.T) {
	store := &stubDeleteStore{
		cfg:      &stubConfig{Values: map[string]string{"key": "val"}},
		path:     "/tmp/test.yaml",
		exists:   true,
		writeErr: errors.New("write failed"),
	}
	editor := &Editor[stubConfig]{
		DeleteStore: store,
		Force:       true,
		IsTTY:       func() bool { return false },
	}

	_, err := editor.Delete("key")
	if err == nil {
		t.Fatal("expected error from Write")
	}
}

func TestEditor_Delete_TTY_Rejected(t *testing.T) {
	store := &stubDeleteStore{
		cfg:    &stubConfig{Values: map[string]string{"key": "val"}},
		path:   "/tmp/test.yaml",
		exists: true,
	}
	var stderr bytes.Buffer
	editor := &Editor[stubConfig]{
		DeleteStore: store,
		Stderr:      &stderr,
		Force:       false,
		IsTTY:       func() bool { return true },
		Confirm:     func(string) bool { return false },
	}

	result, err := editor.Delete("key")
	if err != nil {
		t.Fatalf("Delete error: %v", err)
	}
	if result.Applied {
		t.Error("expected Applied=false when user rejects")
	}
}

func TestEditor_Delete_TTY_Confirmed(t *testing.T) {
	store := &stubDeleteStore{
		cfg:    &stubConfig{Values: map[string]string{"key": "val"}},
		path:   "/tmp/test.yaml",
		exists: true,
	}
	var stderr bytes.Buffer
	editor := &Editor[stubConfig]{
		DeleteStore: store,
		Stderr:      &stderr,
		Force:       false,
		IsTTY:       func() bool { return true },
		Confirm:     func(string) bool { return true },
	}

	result, err := editor.Delete("key")
	if err != nil {
		t.Fatalf("Delete error: %v", err)
	}
	if !result.Applied {
		t.Error("expected Applied=true when user confirms")
	}
}

func TestEditor_Stderr_Fallback(t *testing.T) {
	// When Stderr is nil, stderr() should return os.Stderr (non-nil).
	editor := &Editor[stubConfig]{}
	w := editor.stderr()
	if w == nil {
		t.Fatal("stderr() returned nil")
	}
}
