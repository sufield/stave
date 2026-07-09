package iamauth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMain(m *testing.M) {
	SetDataDir(filepath.Join("testdata"))
	os.Exit(m.Run())
}

func TestLoad(t *testing.T) {
	ref, err := Load("s3")
	if err != nil {
		t.Fatalf("Load(s3): %v", err)
	}
	if ref == nil {
		t.Fatal("expected s3 to be available")
	}
	if ref.Name != "s3" {
		t.Errorf("Name = %q, want s3", ref.Name)
	}
	if len(ref.Actions) < 50 {
		t.Errorf("expected 50+ S3 actions, got %d", len(ref.Actions))
	}
	if len(ref.ConditionKeys) < 10 {
		t.Errorf("expected 10+ S3 condition keys, got %d", len(ref.ConditionKeys))
	}
	if len(ref.Resources) < 5 {
		t.Errorf("expected 5+ S3 resource types, got %d", len(ref.Resources))
	}
}

func TestLoadUnknown(t *testing.T) {
	ref, err := Load("nonexistent-service-xyz-9999")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref != nil {
		t.Error("expected nil for unknown service")
	}
}

func TestLoadIndex(t *testing.T) {
	index, err := LoadIndex()
	if err != nil {
		t.Fatalf("LoadIndex(): %v", err)
	}
	if len(index) < 3 {
		t.Errorf("expected 3+ index entries, got %d", len(index))
	}
	for _, entry := range index {
		if entry.Service == "" {
			t.Error("empty service in index entry")
		}
		if entry.Modified == 0 {
			t.Errorf("zero modified for %s", entry.Service)
		}
	}
}

func TestActionRegistry(t *testing.T) {
	ref, err := Load("s3")
	if err != nil {
		t.Fatalf("Load(s3): %v", err)
	}

	ar := NewActionRegistry(ref)

	tests := []struct {
		action string
		want   bool
	}{
		{"GetObject", true},
		{"PutObject", true},
		{"FakeAction", false},
		{"getobject", true}, // case insensitive
	}

	for _, tt := range tests {
		if got := ar.Valid(tt.action); got != tt.want {
			t.Errorf("ActionRegistry.Valid(%q) = %v, want %v", tt.action, got, tt.want)
		}
	}

	all := ar.All()
	if len(all) < 50 {
		t.Errorf("expected 50+ actions in All(), got %d", len(all))
	}
}

func TestConditionKeyRegistry(t *testing.T) {
	ref, err := Load("s3")
	if err != nil {
		t.Fatalf("Load(s3): %v", err)
	}

	ckr := NewConditionKeyRegistry(ref)

	tests := []struct {
		key  string
		want bool
	}{
		{"s3:prefix", true},
		{"s3:TlsVersion", true},
		{"aws:RequestTag/Environment", true}, // parameterized
		{"totally:bogus:key", false},
	}

	for _, tt := range tests {
		if got := ckr.Valid(tt.key); got != tt.want {
			t.Errorf("ConditionKeyRegistry.Valid(%q) = %v, want %v", tt.key, got, tt.want)
		}
	}

	typ := ckr.KeyType("s3:prefix")
	if typ != "String" {
		t.Errorf("KeyType(s3:prefix) = %q, want String", typ)
	}
}

func TestResourceTypeRegistry(t *testing.T) {
	ref, err := Load("s3")
	if err != nil {
		t.Fatalf("Load(s3): %v", err)
	}

	rtr := NewResourceTypeRegistry(ref)

	if !rtr.Valid("bucket") {
		t.Error("expected bucket to be valid")
	}
	if rtr.Valid("nonexistent") {
		t.Error("expected nonexistent to be invalid")
	}

	arns := rtr.ARNFormats("bucket")
	if len(arns) == 0 {
		t.Error("expected ARN formats for bucket")
	}

	all := rtr.All()
	if len(all) < 5 {
		t.Errorf("expected 5+ resource types, got %d", len(all))
	}
}

func TestActionConditionKeys(t *testing.T) {
	ref, err := Load("s3")
	if err != nil {
		t.Fatalf("Load(s3): %v", err)
	}

	keys := ActionConditionKeys(ref, "GetObject")
	if len(keys) == 0 {
		t.Error("expected condition keys for s3:GetObject")
	}

	keys = ActionConditionKeys(ref, "FakeAction")
	if keys != nil {
		t.Errorf("expected nil for unknown action, got %v", keys)
	}
}

func TestActionResources(t *testing.T) {
	ref, err := Load("s3")
	if err != nil {
		t.Fatalf("Load(s3): %v", err)
	}

	resources := ActionResources(ref, "GetObject")
	if len(resources) == 0 {
		t.Error("expected resource types for s3:GetObject")
	}
}

func TestDependentActions_PassRole(t *testing.T) {
	ref, err := Load("lambda")
	if err != nil {
		t.Fatalf("Load(lambda): %v", err)
	}

	deps := DependentActions(ref, "CreateFunction")
	if len(deps) == 0 {
		t.Fatal("expected dependent actions for lambda:CreateFunction")
	}

	var foundPassRole bool
	for _, dep := range deps {
		if dep.Service == "iam" && dep.Name == "PassRole" {
			foundPassRole = true
			if len(dep.Context) == 0 {
				t.Error("expected Context on PassRole dependency")
			}
		}
	}
	if !foundPassRole {
		t.Error("expected iam:PassRole as dependent action for lambda:CreateFunction")
	}
}

func TestAccessLevel(t *testing.T) {
	tests := []struct {
		props ActionProperties
		want  string
	}{
		{ActionProperties{IsPermissionManagement: true}, "Permissions management"},
		{ActionProperties{IsWrite: true}, "Write"},
		{ActionProperties{IsList: true}, "List"},
		{ActionProperties{IsTaggingOnly: true}, "Tagging"},
		{ActionProperties{}, "Read"},
	}

	for _, tt := range tests {
		if got := tt.props.AccessLevel(); got != tt.want {
			t.Errorf("AccessLevel() = %q, want %q", got, tt.want)
		}
	}
}
