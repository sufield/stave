package main

import (
	"math"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestIsRunnableFixture(t *testing.T) {
	t.Run("command.txt", func(t *testing.T) {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "command.txt"), []byte("apply"), 0o644)
		if !isRunnableFixture(dir) {
			t.Fatal("fixture with command.txt should be runnable")
		}
	})
	t.Run("profile-style", func(t *testing.T) {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "observations.json"), []byte("{}"), 0o644)
		os.WriteFile(filepath.Join(dir, "golden.json"), []byte("{}"), 0o644)
		if !isRunnableFixture(dir) {
			t.Fatal("fixture with observations.json+golden.json should be runnable")
		}
	})
	t.Run("default-apply", func(t *testing.T) {
		dir := t.TempDir()
		os.MkdirAll(filepath.Join(dir, "controls"), 0o755)
		os.MkdirAll(filepath.Join(dir, "observations"), 0o755)
		if !isRunnableFixture(dir) {
			t.Fatal("fixture with controls/+observations/ should be runnable")
		}
	})
	t.Run("empty", func(t *testing.T) {
		dir := t.TempDir()
		if isRunnableFixture(dir) {
			t.Fatal("empty dir should not be runnable")
		}
	})
	t.Run("observations-only", func(t *testing.T) {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "observations.json"), []byte("{}"), 0o644)
		if isRunnableFixture(dir) {
			t.Fatal("observations.json without golden.json should not be runnable")
		}
	})
}

func TestDiffPaths_MarshalError(t *testing.T) {
	// Under the bug, both math.NaN() and math.Inf(1) fail to marshal,
	// resulting in aj=nil and bj=nil. bytes.Equal(nil, nil) evaluates
	// to true, so no diff is reported even though the values differ.
	got := diffPaths(math.NaN(), math.Inf(1), "testpath")
	want := []string{"testpath"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("diffPaths(NaN, Inf) = %v, want %v", got, want)
	}
}
