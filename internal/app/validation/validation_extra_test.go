package validation

import (
	"testing"

	contractvalidator "github.com/sufield/stave/internal/contracts/validator"
)

// ---------------------------------------------------------------------------
// ContentService
// ---------------------------------------------------------------------------

func TestContentService_ValidateObservationJSON(t *testing.T) {
	svc := NewContentService(func() *contractvalidator.Validator {
		return contractvalidator.New()
	})

	data := []byte(`{
		"schema_version": "obs.v0.1",
		"captured_at": "2026-01-15T00:00:00Z",
		"generated_by": {"source_type": "aws-s3-snapshot", "tool": "test"},
		"assets": []
	}`)

	result, err := svc.Validate(AutoRequest{Data: data})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestContentService_ValidateControlYAML(t *testing.T) {
	svc := NewContentService(func() *contractvalidator.Validator {
		return contractvalidator.New()
	})

	data := []byte(`dsl_version: ctrl.v1
id: CTL.TEST.001
name: Test Control
description: Test
type: unsafe_state
unsafe_predicate:
  any:
    - field: "properties.test"
      op: "eq"
      value: true
`)

	result, err := svc.Validate(AutoRequest{Data: data})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestIsLikelyJSONContent(t *testing.T) {
	if !isLikelyJSONContent([]byte(`{"key": "value"}`)) {
		t.Fatal("should detect JSON object")
	}
	if !isLikelyJSONContent([]byte(`[1, 2, 3]`)) {
		t.Fatal("should detect JSON array")
	}
	if isLikelyJSONContent([]byte(`key: value`)) {
		t.Fatal("should not detect YAML as JSON")
	}
	if isLikelyJSONContent([]byte(``)) {
		t.Fatal("should not detect empty as JSON")
	}
	if !isLikelyJSONContent([]byte(`  {  }`)) {
		t.Fatal("should detect whitespace-padded JSON")
	}
}

func TestContentService_ValidateInvalidJSON(t *testing.T) {
	svc := NewContentService(func() *contractvalidator.Validator {
		return contractvalidator.New()
	})

	data := []byte(`{"invalid": "observation"}`)
	result, err := svc.Validate(AutoRequest{Data: data})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	// Should have validation errors for missing required fields
	if result.Valid() {
		t.Fatal("expected validation issues for invalid observation JSON")
	}
}

func TestContentService_ValidateInvalidControlYAML(t *testing.T) {
	svc := NewContentService(func() *contractvalidator.Validator {
		return contractvalidator.New()
	})

	data := []byte(`name: missing required fields`)
	result, err := svc.Validate(AutoRequest{Data: data})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	// Missing dsl_version and id should produce issues
	if result.Valid() {
		t.Fatal("expected validation issues for invalid control YAML")
	}
}
