package artifacts

import (
	"bytes"
	"strings"
	"testing"
)

func TestPolicyInspectorAvailablePacks(t *testing.T) {
	inspector, err := NewInspector()
	if err != nil {
		t.Fatalf("NewInspector: %v", err)
	}
	items := inspector.AvailablePacks()

	var buf bytes.Buffer
	if err := RenderSummary(&buf, items); err != nil {
		t.Fatalf("RenderSummary: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "POLICY PACK") && !strings.Contains(out, "No security policy packs") {
		t.Fatalf("expected header or empty message, got: %s", out)
	}
}

func TestPolicyInspectorInspectUnknown(t *testing.T) {
	inspector, err := NewInspector()
	if err != nil {
		t.Fatalf("NewInspector: %v", err)
	}
	if _, err := inspector.Inspect("nonexistent-pack"); err == nil {
		t.Fatal("expected error for unknown pack")
	}
}
