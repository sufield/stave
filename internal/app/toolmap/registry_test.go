package toolmap

import "testing"

func TestNewRegistry_HasBuiltinTools(t *testing.T) {
	r := NewRegistry()
	all := r.All()
	if len(all) < 5 {
		t.Fatalf("expected at least 5 tools, got %d", len(all))
	}
}

func TestRegistry_ToolByName(t *testing.T) {
	r := NewRegistry()
	tool, ok := r.Tool("pacu")
	if !ok {
		t.Fatal("pacu not found")
	}
	if len(tool.Prerequisites) == 0 {
		t.Error("pacu should have prerequisites")
	}
}

func TestRegistry_ToolsForCapability(t *testing.T) {
	r := NewRegistry()
	tools := r.ToolsForCapability("iam_credential_theft")
	if len(tools) == 0 {
		t.Fatal("expected tools for iam_credential_theft")
	}
	found := false
	for _, tool := range tools {
		if tool.Name == "pacu" {
			found = true
		}
	}
	if !found {
		t.Error("pacu should require iam_credential_theft")
	}
}

func TestRegistry_CapabilitiesForTool(t *testing.T) {
	r := NewRegistry()
	caps := r.CapabilitiesForTool("pacu")
	if len(caps) == 0 {
		t.Fatal("expected capabilities for pacu")
	}
}

func TestRegistry_UnknownTool(t *testing.T) {
	r := NewRegistry()
	_, ok := r.Tool("nonexistent")
	if ok {
		t.Error("nonexistent tool should not be found")
	}
	caps := r.CapabilitiesForTool("nonexistent")
	if caps != nil {
		t.Error("expected nil capabilities for unknown tool")
	}
}

func TestRegistry_AllSorted(t *testing.T) {
	r := NewRegistry()
	all := r.All()
	for i := 1; i < len(all); i++ {
		if all[i].Name < all[i-1].Name {
			t.Errorf("tools not sorted: %s before %s", all[i-1].Name, all[i].Name)
		}
	}
}
