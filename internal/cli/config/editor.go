package config

import (
	"fmt"
	"io"
	"os"
)

// SetStore defines the data operations required for config set mutations.
type SetStore[T any] interface {
	LoadOrCreate() (cfg *T, path string, err error)
	CurrentValue(cfg *T, key, path string) string
	Set(cfg *T, key, value string) error
	Write(path string, cfg *T) error
}

// DeleteStore defines the data operations required for config delete mutations.
type DeleteStore[T any] interface {
	Find() (cfg *T, path string, exists bool)
	Delete(cfg *T, key string) error
	Write(path string, cfg *T) error
}

// Editor coordinates set/delete mutations for project config.
// It is generic so cmd can provide its concrete config model.
type Editor[T any] struct {
	SetStore    SetStore[T]
	DeleteStore DeleteStore[T]
	Stderr      io.Writer
	Force       bool
	IsTTY       func() bool
	Confirm     func(prompt string) bool
}

// MutationResult captures the outcome of a config mutation attempt.
type MutationResult struct {
	Key     string
	Value   string
	Path    string
	Applied bool
}

// Set mutates or creates project config and writes it when confirmed.
func (m *Editor[T]) Set(key, value string) (MutationResult, error) {
	cfg, cfgPath, err := m.SetStore.LoadOrCreate()
	if err != nil {
		return MutationResult{}, err
	}

	oldValue := m.SetStore.CurrentValue(cfg, key, cfgPath)

	if err := m.SetStore.Set(cfg, key, value); err != nil {
		return MutationResult{}, err
	}
	if !m.confirmSetChange(key, oldValue, value, cfgPath) {
		return MutationResult{Key: key, Value: value, Path: cfgPath, Applied: false}, nil
	}
	if err := m.SetStore.Write(cfgPath, cfg); err != nil {
		return MutationResult{}, err
	}
	return MutationResult{Key: key, Value: value, Path: cfgPath, Applied: true}, nil
}

// Delete removes a key from project config and writes it when confirmed.
func (m *Editor[T]) Delete(key string) (MutationResult, error) {
	cfg, cfgPath, existed := m.DeleteStore.Find()
	if !existed {
		return MutationResult{}, fmt.Errorf("no config file found — nothing to delete")
	}

	if err := m.DeleteStore.Delete(cfg, key); err != nil {
		return MutationResult{}, err
	}
	if !m.confirmDeleteChange(key, cfgPath) {
		return MutationResult{Key: key, Path: cfgPath, Applied: false}, nil
	}
	if err := m.DeleteStore.Write(cfgPath, cfg); err != nil {
		return MutationResult{}, err
	}
	return MutationResult{Key: key, Path: cfgPath, Applied: true}, nil
}

func (m *Editor[T]) confirmSetChange(key, oldValue, newValue, path string) bool {
	if m.Force || !m.IsTTY() {
		return true
	}
	errOut := m.stderr()
	fmt.Fprintf(errOut, "\n  %s: %s -> %s\n  file: %s\n\n", key, oldValue, newValue, path)
	if m.Confirm("Apply?") {
		return true
	}
	fmt.Fprintln(errOut, "Aborted.")
	return false
}

func (m *Editor[T]) confirmDeleteChange(key, path string) bool {
	if m.Force || !m.IsTTY() {
		return true
	}
	errOut := m.stderr()
	if m.Confirm(fmt.Sprintf("Delete %s from %s?", key, path)) {
		return true
	}
	fmt.Fprintln(errOut, "Aborted.")
	return false
}

func (m *Editor[T]) stderr() io.Writer {
	if m.Stderr == nil {
		return os.Stderr
	}
	return m.Stderr
}
