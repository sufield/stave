package fsutil

import (
	"os"
	"testing"
)

func TestSafeDir_RejectsParentTraversal(t *testing.T) {
	cwd, _ := os.Getwd()
	_, err := SafeDir("../../../etc/passwd", cwd)
	if err == nil {
		t.Error("expected error for parent traversal")
	}
}

func TestSafeDir_AcceptsSubdirectory(t *testing.T) {
	cwd, _ := os.Getwd()
	abs, err := SafeDir("testdata/sub", cwd)
	if err != nil {
		t.Errorf("expected no error for subdirectory, got: %v", err)
	}
	if abs == "" {
		t.Error("expected non-empty resolved path")
	}
}

func TestSafeDir_AcceptsCurrentDir(t *testing.T) {
	cwd, _ := os.Getwd()
	_, err := SafeDir(".", cwd)
	if err != nil {
		t.Errorf("expected no error for current dir, got: %v", err)
	}
}

func TestSafeFilename_RejectsForwardSlash(t *testing.T) {
	if err := SafeFilename("foo/bar"); err == nil {
		t.Error("expected error for forward slash")
	}
}

func TestSafeFilename_RejectsBackslash(t *testing.T) {
	if err := SafeFilename(`foo\bar`); err == nil {
		t.Error("expected error for backslash")
	}
}

func TestSafeFilename_AcceptsValidControlID(t *testing.T) {
	if err := SafeFilename("CTL.S3.PUBLIC.001"); err != nil {
		t.Errorf("expected no error for valid control ID, got: %v", err)
	}
}

func TestSafeFilename_RejectsEmpty(t *testing.T) {
	if err := SafeFilename(""); err == nil {
		t.Error("expected error for empty string")
	}
}
