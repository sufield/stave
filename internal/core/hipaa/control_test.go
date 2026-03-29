package hipaa

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
)

// --- Severity tests ---

func TestSeverity_Less(t *testing.T) {
	tests := []struct {
		a, b Severity
		want bool
	}{
		{Low, Medium, true},
		{Medium, High, true},
		{High, Critical, true},
		{Critical, Critical, false},
		{High, Low, false},
		{Low, Low, false},
	}
	for _, tc := range tests {
		t.Run(tc.a.String()+"<"+tc.b.String(), func(t *testing.T) {
			if got := tc.a.Less(tc.b); got != tc.want {
				t.Errorf("(%s).Less(%s) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestSeverity_IsValid(t *testing.T) {
	tests := []struct {
		s    Severity
		want bool
	}{
		{Critical, true},
		{High, true},
		{Medium, true},
		{Low, true},
		{Severity("UNKNOWN"), false},
		{Severity(""), false},
	}
	for _, tc := range tests {
		t.Run(string(tc.s), func(t *testing.T) {
			if got := tc.s.IsValid(); got != tc.want {
				t.Errorf("IsValid() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseSeverity(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		s, err := ParseSeverity("CRITICAL")
		if err != nil {
			t.Fatal(err)
		}
		if s != Critical {
			t.Errorf("got %s", s)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		_, err := ParseSeverity("EXTREME")
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

// --- Definition + functional options tests ---

func TestDefinition_Build(t *testing.T) {
	def := Build(
		WithID("ACCESS.001"),
		WithDescription("Block public access must be fully enabled"),
		WithSeverity(Critical),
		WithComplianceProfiles("hipaa", "pci-dss"),
		WithComplianceRef("hipaa", "§164.312(b)"),
	)

	if def.ID() != "ACCESS.001" {
		t.Errorf("ID: got %q", def.ID())
	}
	if def.Severity() != Critical {
		t.Errorf("Severity: got %s", def.Severity())
	}
	if len(def.ComplianceProfiles()) != 2 {
		t.Errorf("ComplianceProfiles: got %d", len(def.ComplianceProfiles()))
	}
	if def.ComplianceRefs()["hipaa"] != "§164.312(b)" {
		t.Errorf("ComplianceRefs: got %v", def.ComplianceRefs())
	}
}

func TestDefinition_PassResult(t *testing.T) {
	def := Build(WithID("X.001"), WithSeverity(Low))
	r := def.PassResult()
	if !r.Pass {
		t.Error("expected pass")
	}
	if r.ControlID != "X.001" {
		t.Errorf("ControlID: got %q", r.ControlID)
	}
}

func TestDefinition_FailResult(t *testing.T) {
	def := Build(
		WithID("X.002"),
		WithSeverity(High),
		WithComplianceRef("cis", "1.2.3"),
	)
	r := def.FailResult("bucket is public", "enable BPA")
	if r.Pass {
		t.Error("expected fail")
	}
	if r.Finding != "bucket is public" {
		t.Errorf("Finding: got %q", r.Finding)
	}
	if r.Remediation != "enable BPA" {
		t.Errorf("Remediation: got %q", r.Remediation)
	}
	if r.ComplianceRefs["cis"] != "1.2.3" {
		t.Errorf("ComplianceRefs: got %v", r.ComplianceRefs)
	}
}

// --- Registry tests ---

// stubControl implements Control for testing.
type stubControl struct {
	Definition
}

func (s *stubControl) Evaluate(_ asset.Snapshot) Result {
	return s.PassResult()
}

func newStub(id string, sev Severity) *stubControl {
	return &stubControl{
		Definition: Build(WithID(id), WithSeverity(sev)),
	}
}

func TestRegistry_Register_And_Lookup(t *testing.T) {
	reg := NewRegistry()
	inv := newStub("ACCESS.001", Critical)

	if err := reg.Register(inv); err != nil {
		t.Fatalf("register: %v", err)
	}

	got := reg.Lookup("ACCESS.001")
	if got == nil {
		t.Fatal("lookup returned nil")
	}
	if got.ID() != "ACCESS.001" {
		t.Errorf("ID: got %q", got.ID())
	}
}

func TestRegistry_Lookup_Missing(t *testing.T) {
	reg := NewRegistry()
	if got := reg.Lookup("NONEXISTENT"); got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestRegistry_Duplicate_Registration(t *testing.T) {
	reg := NewRegistry()
	inv := newStub("ACCESS.001", High)

	if err := reg.Register(inv); err != nil {
		t.Fatalf("first register: %v", err)
	}
	if err := reg.Register(inv); err == nil {
		t.Fatal("expected error on duplicate registration")
	}
}

func TestRegistry_All_Preserves_Order(t *testing.T) {
	reg := NewRegistry()
	reg.MustRegister(newStub("C.001", Low))
	reg.MustRegister(newStub("A.001", High))
	reg.MustRegister(newStub("B.001", Medium))

	all := reg.All()
	if len(all) != 3 {
		t.Fatalf("Len: got %d", len(all))
	}
	if all[0].ID() != "C.001" || all[1].ID() != "A.001" || all[2].ID() != "B.001" {
		t.Errorf("order: got %s, %s, %s", all[0].ID(), all[1].ID(), all[2].ID())
	}
}

func TestRegistry_Len(t *testing.T) {
	reg := NewRegistry()
	if reg.Len() != 0 {
		t.Errorf("empty: got %d", reg.Len())
	}
	reg.MustRegister(newStub("X.001", Low))
	if reg.Len() != 1 {
		t.Errorf("after register: got %d", reg.Len())
	}
}

func TestRegistry_MustRegister_Panics_On_Duplicate(t *testing.T) {
	reg := NewRegistry()
	reg.MustRegister(newStub("X.001", Low))

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on duplicate MustRegister")
		}
	}()
	reg.MustRegister(newStub("X.001", Low))
}
