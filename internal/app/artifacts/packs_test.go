package artifacts

import (
	"bytes"
	"strings"
	"testing"
)

func TestPackRunnerList(t *testing.T) {
	runner, err := NewPackRunner()
	if err != nil {
		t.Fatalf("NewPackRunner: %v", err)
	}
	items := runner.List()

	var buf bytes.Buffer
	if err := WritePackList(&buf, items); err != nil {
		t.Fatalf("WritePackList: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "NAME") && !strings.Contains(out, "No built-in packs") {
		t.Fatalf("expected header or empty message, got: %s", out)
	}
}

func TestPackRunnerShowUnknown(t *testing.T) {
	runner, err := NewPackRunner()
	if err != nil {
		t.Fatalf("NewPackRunner: %v", err)
	}
	if _, err := runner.Show("nonexistent-pack"); err == nil {
		t.Fatal("expected error for unknown pack")
	}
}
