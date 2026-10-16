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

func TestPrerequisites_DomainMethods(t *testing.T) {
	ps := Prerequisites{
		{Capability: "iam_credential_theft", FieldPath: "properties.identity.policies"},
		{Capability: "s3_public_bucket", FieldPath: "properties.policy.public"},
		{Capability: "iam_credential_theft", FieldPath: "properties.roles.assume"},
	}

	if ps.Len() != 3 {
		t.Errorf("Len() = %d, want 3", ps.Len())
	}

	caps := ps.Capabilities()
	if len(caps) != 2 {
		t.Fatalf("Capabilities() len = %d, want 2 (deduped)", len(caps))
	}
	if caps[0] != "iam_credential_theft" || caps[1] != "s3_public_bucket" {
		t.Errorf("Capabilities() = %v, want [iam_credential_theft, s3_public_bucket]", caps)
	}

	if !ps.HasCapability("iam_credential_theft") {
		t.Error("HasCapability(iam_credential_theft) = false, want true")
	}
	if ps.HasCapability("privesc") {
		t.Error("HasCapability(privesc) = true, want false")
	}

	filtered := ps.ByCapability("iam_credential_theft")
	if filtered.Len() != 2 {
		t.Errorf("ByCapability(iam_credential_theft).Len() = %d, want 2", filtered.Len())
	}

	paths := ps.FieldPaths()
	if len(paths) != 3 {
		t.Fatalf("FieldPaths() len = %d, want 3", len(paths))
	}
	if paths[0] != "properties.identity.policies" {
		t.Errorf("FieldPaths()[0] = %q, want properties.identity.policies", paths[0])
	}

	var empty Prerequisites
	if empty.Len() != 0 {
		t.Errorf("empty.Len() = %d, want 0", empty.Len())
	}
	if empty.Capabilities() != nil {
		t.Error("empty.Capabilities() should return nil")
	}
	if empty.HasCapability("any") {
		t.Error("empty.HasCapability() should return false")
	}
	if empty.ByCapability("any") != nil {
		t.Error("empty.ByCapability() should return nil")
	}
	if empty.FieldPaths() != nil {
		t.Error("empty.FieldPaths() should return nil")
	}
}

func TestTools_DomainMethods(t *testing.T) {
	tools := Tools{
		{Name: "pacu", Description: "AWS exploitation framework"},
		{Name: "prowler", Description: "Security assessment tool"},
	}

	if tools.Len() != 2 {
		t.Errorf("tools.Len() = %d, want 2", tools.Len())
	}

	names := tools.Names()
	if len(names) != 2 || names[0] != "pacu" || names[1] != "prowler" {
		t.Errorf("Names() = %v, want [pacu, prowler]", names)
	}

	p := tools.ByName("pacu")
	if p == nil || p.Name != "pacu" {
		t.Errorf("ByName(pacu) = %v, want pacu", p)
	}

	unknown := tools.ByName("unknown")
	if unknown != nil {
		t.Errorf("ByName(unknown) = %v, want nil", unknown)
	}

	var empty Tools
	if empty.Len() != 0 {
		t.Errorf("empty.Len() = %d, want 0", empty.Len())
	}
	if empty.Names() != nil {
		t.Error("empty.Names() should return nil")
	}
	if empty.ByName("pacu") != nil {
		t.Error("empty.ByName() should return nil")
	}
}
