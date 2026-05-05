package yaml

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
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

func TestUnmarshalControlDefinition_Archetype(t *testing.T) {
	data := []byte(`
dsl_version: ctrl.v1
id: CTL.TEST.002
name: Test with archetype
description: Test control
type: unsafe_state
archetype: ghost-reference
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
	if ctl.Archetype != "ghost-reference" {
		t.Errorf("Archetype = %q, want %q", ctl.Archetype, "ghost-reference")
	}
}

func TestUnmarshalControlDefinition_ArchetypeAbsent(t *testing.T) {
	data := []byte(`
dsl_version: ctrl.v1
id: CTL.TEST.003
name: Test without archetype
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
	if ctl.Archetype != "" {
		t.Errorf("Archetype = %q, want empty", ctl.Archetype)
	}
}

// TestUnmarshalControlDefinition_IntentRationaleAndForbiddenState
// pins the Iter 5.1 schema additions: a YAML control authored with
// the new fields parses cleanly into the domain ControlDefinition,
// preserving both the rationale prose and the invariant predicate
// shape.
func TestUnmarshalControlDefinition_IntentRationaleAndForbiddenState(t *testing.T) {
	data := []byte(`
dsl_version: ctrl.v1
id: CTL.TEST.INVARIANT.001
name: Public bucket invariant
description: Detect public S3 buckets
type: unsafe_state
intent_rationale: |
  Public S3 buckets violate data-residency invariants required by
  the org's compliance posture.
forbidden_state:
  all:
    - field: "properties.principal"
      op: "eq"
      value: "*"
    - field: "properties.network"
      op: "eq"
      value: "public"
unsafe_predicate:
  any:
    - field: "properties.public"
      op: "eq"
      value: true
`)
	ctl, err := UnmarshalControlDefinition(data)
	if err != nil {
		t.Fatalf("UnmarshalControlDefinition: %v", err)
	}
	if ctl.IntentRationale == "" {
		t.Errorf("IntentRationale empty; want non-empty prose")
	}
	if ctl.ForbiddenState.IsEmpty() {
		t.Fatalf("ForbiddenState empty; want populated")
	}
	if got := len(ctl.ForbiddenState.All); got != 2 {
		t.Errorf("ForbiddenState.All: want 2 rules, got %d", got)
	}
	// UnsafePredicate is unchanged.
	if got := len(ctl.UnsafePredicate.Any); got != 1 {
		t.Errorf("UnsafePredicate.Any: want 1 rule, got %d", got)
	}
}

// TestUnmarshalControlDefinition_IntentFieldsAbsent verifies the
// new fields are optional — absence renders as empty rationale and
// empty forbidden_state, no error.
func TestUnmarshalControlDefinition_IntentFieldsAbsent(t *testing.T) {
	data := []byte(`
dsl_version: ctrl.v1
id: CTL.TEST.INVARIANT.002
name: No-intent control
description: Same control without intent fields
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
	if ctl.IntentRationale != "" {
		t.Errorf("IntentRationale: want empty, got %q", ctl.IntentRationale)
	}
	if !ctl.ForbiddenState.IsEmpty() {
		t.Errorf("ForbiddenState: want empty, got %+v", ctl.ForbiddenState)
	}
}

func TestUnmarshalControlDefinition_InvalidYAML(t *testing.T) {
	data := []byte(": [bad yaml")
	_, err := UnmarshalControlDefinition(data)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

// TestValidateArchetype_RejectsUnknown confirms enrichAndPrepare
// rejects controls whose archetype field references an ID the catalog
// doesn't know about. Typo'd archetype IDs used to load successfully
// and silently disappear into the "no archetype" downstream branch.
func TestValidateArchetype_RejectsUnknown(t *testing.T) {
	ctl := policy.ControlDefinition{
		ID:        "CTL.TEST.999",
		Archetype: "silent_failure", // typo — catalog has silent-failure
	}
	if err := validateArchetype(&ctl); err == nil {
		t.Fatal("expected error for unknown archetype id, got nil")
	}
}

func TestValidateArchetype_AcceptsKnown(t *testing.T) {
	ctl := policy.ControlDefinition{
		ID:        "CTL.TEST.998",
		Archetype: "silent-failure",
	}
	if err := validateArchetype(&ctl); err != nil {
		t.Fatalf("expected known archetype to validate, got: %v", err)
	}
}

func TestValidateArchetype_AcceptsEmpty(t *testing.T) {
	ctl := policy.ControlDefinition{ID: "CTL.TEST.997"}
	if err := validateArchetype(&ctl); err != nil {
		t.Fatalf("empty archetype must validate, got: %v", err)
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
  recurrence_threshold: 3
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
