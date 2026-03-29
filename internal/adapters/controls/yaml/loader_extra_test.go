package yaml

import (
	"testing"
)

func TestIsControlFile(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"control.yaml", true},
		{"control.yml", true},
		{"control.json", false},
		{"control.example.yaml", false},
		{"control.example.yml", false},
		{".hidden.yaml", false},
		{"readme.txt", false},
		{"CONTROL.YAML", true}, // ext is lowered
	}
	for _, tt := range tests {
		got := isControlFile(tt.path)
		if got != tt.want {
			t.Errorf("isControlFile(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestUnmarshalControlDefinition_MinimalValid(t *testing.T) {
	data := []byte(`
dsl_version: ctrl.v1
id: CTL.TEST.001
name: Test
description: Test control
type: unsafe_state
unsafe_predicate:
  any:
    - field: "properties.x"
      op: "eq"
      value: true
`)
	ctl, err := UnmarshalControlDefinition(data)
	if err != nil {
		t.Fatalf("UnmarshalControlDefinition: %v", err)
	}
	if ctl.ID != "CTL.TEST.001" {
		t.Fatalf("ID = %q", ctl.ID)
	}
	if ctl.Name != "Test" {
		t.Fatalf("Name = %q", ctl.Name)
	}
}

func TestUnmarshalControlDefinition_InvalidYAML(t *testing.T) {
	data := []byte(": [bad yaml")
	_, err := UnmarshalControlDefinition(data)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestUnmarshalControlDefinition_WithExposure(t *testing.T) {
	data := []byte(`
dsl_version: ctrl.v1
id: CTL.TEST.EXP.001
name: Exposure Test
description: Test exposure field
type: unsafe_state
exposure:
  type: public_read
  principal_scope: public
unsafe_predicate:
  any:
    - field: "properties.x"
      op: "eq"
      value: true
`)
	ctl, err := UnmarshalControlDefinition(data)
	if err != nil {
		t.Fatalf("UnmarshalControlDefinition: %v", err)
	}
	if ctl.Exposure == nil {
		t.Fatal("Exposure should not be nil")
	}
}

func TestUnmarshalControlDefinition_WithParams(t *testing.T) {
	data := []byte(`
dsl_version: ctrl.v1
id: CTL.TEST.PAR.001
name: Param Test
description: Test params field
type: unsafe_state
params:
  max_unsafe_duration: "168h"
  recurrence_limit: 3
unsafe_predicate:
  any:
    - field: "properties.x"
      op: "eq"
      value: true
`)
	ctl, err := UnmarshalControlDefinition(data)
	if err != nil {
		t.Fatalf("UnmarshalControlDefinition: %v", err)
	}
	if ctl.Params.IsZero() {
		t.Fatal("Params should not be zero")
	}
}

func TestUnmarshalControlDefinition_WithCompliance(t *testing.T) {
	data := []byte(`
dsl_version: ctrl.v1
id: CTL.TEST.COMP.001
name: Compliance Test
description: Test compliance mapping
type: unsafe_state
compliance:
  hipaa: "164.312(a)(1)"
  nist_800_53: "SC-13"
unsafe_predicate:
  any:
    - field: "properties.x"
      op: "eq"
      value: true
`)
	ctl, err := UnmarshalControlDefinition(data)
	if err != nil {
		t.Fatalf("UnmarshalControlDefinition: %v", err)
	}
	if ctl.Compliance.Get("hipaa") != "164.312(a)(1)" {
		t.Fatalf("hipaa = %q", ctl.Compliance.Get("hipaa"))
	}
}
