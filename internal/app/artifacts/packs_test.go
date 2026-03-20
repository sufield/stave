package artifacts

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestPackRunnerList(t *testing.T) {
	var buf bytes.Buffer
	runner, err := NewPackRunner(&buf)
	if err != nil {
		t.Fatalf("NewPackRunner: %v", err)
	}
	if err := runner.List(context.Background()); err != nil {
		t.Fatalf("List: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "NAME") && !strings.Contains(out, "No built-in packs") {
		t.Fatalf("expected header or empty message, got: %s", out)
	}
}

func TestPackRunnerShowUnknown(t *testing.T) {
	var buf bytes.Buffer
	runner, err := NewPackRunner(&buf)
	if err != nil {
		t.Fatalf("NewPackRunner: %v", err)
	}
	if err := runner.Show(context.Background(), "nonexistent-pack"); err == nil {
		t.Fatal("expected error for unknown pack")
	}
}
