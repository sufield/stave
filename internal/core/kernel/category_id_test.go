package kernel

import "testing"

func TestCategoryID_Validate_Empty(t *testing.T) {
	var c CategoryID
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for empty CategoryID")
	}
}

func TestCategoryID_Validate_NoVocabulary(t *testing.T) {
	c := CategoryID("anything")
	if err := c.Validate(); err != nil {
		t.Fatalf("no vocabulary registered — should accept any non-empty ID, got: %v", err)
	}
}

func TestCategoryID_Validate_WithVocabulary(t *testing.T) {
	SetCategoryIDVocabulary([]string{"trust-boundary", "logging"})
	defer SetCategoryIDVocabulary(nil)

	if err := CategoryID("trust-boundary").Validate(); err != nil {
		t.Fatalf("valid ID rejected: %v", err)
	}
	if err := CategoryID("trsut-boundary").Validate(); err == nil {
		t.Fatal("typo should be rejected when vocabulary is registered")
	}
}

func TestCategoryID_UnmarshalText(t *testing.T) {
	SetCategoryIDVocabulary([]string{"logging"})
	defer SetCategoryIDVocabulary(nil)

	var c CategoryID
	if err := c.UnmarshalText([]byte("logging")); err != nil {
		t.Fatalf("valid unmarshal failed: %v", err)
	}
	if c != "logging" {
		t.Fatalf("got %q", c)
	}

	if err := c.UnmarshalText([]byte("loging")); err == nil {
		t.Fatal("typo should fail unmarshal")
	}
}

func TestCategoryID_IsValid(t *testing.T) {
	SetCategoryIDVocabulary([]string{"formal-semantics"})
	defer SetCategoryIDVocabulary(nil)

	if CategoryID("").IsValid() {
		t.Fatal("empty should be invalid")
	}
	if !CategoryID("formal-semantics").IsValid() {
		t.Fatal("known ID should be valid")
	}
	if CategoryID("formal-semnatics").IsValid() {
		t.Fatal("typo should be invalid")
	}
}
