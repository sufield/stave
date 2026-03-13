package validator

import (
	"testing"

	schemas "github.com/sufield/stave/internal/contracts/schema"
)

func TestValidateControlV1Valid(t *testing.T) {
	v := New()
	diags, err := v.Validate(Request{
		Kind: schemas.KindControl, ActualVersion: "v1", IsYAML: true,
		Data: []byte(`
dsl_version: ctrl.v1
id: CTL.S3.PUBLIC.001
name: Buckets should stay private
description: Public buckets increase exposure risk.
type: unsafe_state
unsafe_predicate:
  any:
    - field: properties.storage.visibility.public_read
      op: eq
      value: true
`),
	})
	if err != nil {
		t.Fatalf("validate control failed: %v", err)
	}
	if len(diags) > 0 {
		t.Fatalf("expected no diagnostics, got %#v", diags)
	}
}

func TestValidateControlV1UnknownField(t *testing.T) {
	v := New()
	diags, err := v.Validate(Request{
		Kind: schemas.KindControl, ActualVersion: "v1", IsYAML: true,
		Data: []byte(`
dsl_version: ctrl.v1
id: CTL.S3.PUBLIC.001
name: Buckets should stay private
description: Public buckets increase exposure risk.
type: unsafe_state
unsafe_predicate:
  any:
    - field: properties.storage.visibility.public_read
      op: eq
      value: true
unknown_field: true
`),
	})
	if err != nil {
		t.Fatalf("validate control failed: %v", err)
	}
	if len(diags) == 0 {
		t.Fatal("expected diagnostics for unknown field")
	}
}

func TestValidateControlV1RejectsInvalidShape(t *testing.T) {
	v := New()
	diags, err := v.Validate(Request{
		Kind: schemas.KindControl, ActualVersion: "v1", IsYAML: true,
		Data: []byte(`
dsl_version: ctrl.v1
id: CTL.S3.PUBLIC.001
name: Bad shape
description: Invalid metadata shape
control: public_access
expect: disabled
`),
	})
	if err != nil {
		t.Fatalf("validate control failed: %v", err)
	}
	if len(diags) == 0 {
		t.Fatal("expected diagnostics for invalid control shape")
	}
}

func TestValidateFindingV1Pass(t *testing.T) {
	v := New()
	payload := []byte(`{
  "control_id":"CTL.S3.PUBLIC.001",
  "control_name":"Public bucket",
  "control_description":"Bucket is public.",
  "asset_id":"bucket-1",
  "asset_type":"storage_bucket",
  "asset_vendor":"aws",
  "evidence":{
    "first_seen_unsafe":"2026-01-01T00:00:00Z",
    "unsafe_duration_hours":48,
    "threshold_hours":24,
    "reason":"public"
  },
  "remediation":{
    "description":"remove public access",
    "action":"disable public access"
  }
}`)
	diags, err := v.Validate(Request{Kind: schemas.KindFinding, ActualVersion: "v1", Data: payload})
	if err != nil {
		t.Fatalf("validate finding failed: %v", err)
	}
	if len(diags) > 0 {
		t.Fatalf("expected no diagnostics, got %#v", diags)
	}
}

func TestValidator_ZeroValueUsable(t *testing.T) {
	v := New()
	diags, err := v.Validate(Request{
		Kind: schemas.KindFinding, ActualVersion: "v1",
		Data: []byte(`{
  "control_id":"CTL.S3.PUBLIC.001",
  "control_name":"Public bucket",
  "control_description":"Bucket is public.",
  "asset_id":"bucket-1",
  "asset_type":"storage_bucket",
  "asset_vendor":"aws",
  "evidence":{
    "first_seen_unsafe":"2026-01-01T00:00:00Z",
    "unsafe_duration_hours":48,
    "threshold_hours":24,
    "reason":"public"
  },
  "remediation":{
    "description":"remove public access",
    "action":"disable public access"
  }
}`),
	})
	if err != nil {
		t.Fatalf("zero-value validator failed: %v", err)
	}
	if len(diags) > 0 {
		t.Fatalf("expected no diagnostics, got %#v", diags)
	}
}
