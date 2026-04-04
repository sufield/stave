package compliance

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// --- Severity tests (delegated to policy.Severity / controldef) ---

func TestSeverity_Less(t *testing.T) {
	tests := []struct {
		a, b policy.Severity
		want bool
	}{
		{policy.SeverityLow, policy.SeverityMedium, true},
		{policy.SeverityMedium, policy.SeverityHigh, true},
		{policy.SeverityHigh, policy.SeverityCritical, true},
		{policy.SeverityCritical, policy.SeverityCritical, false},
		{policy.SeverityHigh, policy.SeverityLow, false},
		{policy.SeverityLow, policy.SeverityLow, false},
	}
	for _, tc := range tests {
		t.Run(tc.a.String()+"<"+tc.b.String(), func(t *testing.T) {
			if got := tc.a < tc.b; got != tc.want {
				t.Errorf("(%s) < (%s) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestSeverity_IsValid(t *testing.T) {
	tests := []struct {
		s    policy.Severity
		want bool
	}{
		{policy.SeverityCritical, true},
		{policy.SeverityHigh, true},
		{policy.SeverityMedium, true},
		{policy.SeverityLow, true},
		{policy.SeverityNone, false},
		{policy.Severity(99), false},
	}
	for _, tc := range tests {
		t.Run(tc.s.String(), func(t *testing.T) {
			if got := tc.s.IsValid(); got != tc.want {
				t.Errorf("IsValid() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseSeverity(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		s, err := policy.ParseSeverity("critical")
		if err != nil {
			t.Fatal(err)
		}
		if s != policy.SeverityCritical {
			t.Errorf("got %s", s)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		_, err := policy.ParseSeverity("EXTREME")
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

// --- Definition + functional options tests ---

func TestDefinition_Build(t *testing.T) {
	def := NewDefinition(
		WithID("ACCESS.001"),
		WithDescription("Block public access must be fully enabled"),
		WithSeverity(policy.SeverityCritical),
		WithComplianceProfiles("hipaa", "pci-dss"),
		WithComplianceRef("hipaa", "§164.312(b)"),
	)

	if def.Def().ID() != "ACCESS.001" {
		t.Errorf("ID: got %q", def.Def().ID())
	}
	if def.Severity() != policy.SeverityCritical {
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
	def := NewDefinition(WithID("X.001"), WithSeverity(policy.SeverityLow))
	r := def.PassResult()
	if !r.Pass {
		t.Error("expected pass")
	}
	if r.ControlID != "X.001" {
		t.Errorf("ControlID: got %q", r.ControlID)
	}
}

func TestDefinition_FailResult(t *testing.T) {
	def := NewDefinition(
		WithID("X.002"),
		WithSeverity(policy.SeverityHigh),
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

func newStub(id kernel.ControlID, sev policy.Severity) *stubControl {
	return &stubControl{
		Definition: NewDefinition(WithID(id), WithSeverity(sev)),
	}
}

func TestRegistry_Register_And_Lookup(t *testing.T) {
	reg := NewRegistry()
	ctl := newStub("ACCESS.001", policy.SeverityCritical)

	if err := reg.Register(ctl); err != nil {
		t.Fatalf("register: %v", err)
	}

	got := reg.Lookup("ACCESS.001")
	if got == nil {
		t.Fatal("lookup returned nil")
	}
	if got.Def().ID() != "ACCESS.001" {
		t.Errorf("ID: got %q", got.Def().ID())
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
	ctl := newStub("ACCESS.001", policy.SeverityHigh)

	if err := reg.Register(ctl); err != nil {
		t.Fatalf("first register: %v", err)
	}
	if err := reg.Register(ctl); err == nil {
		t.Fatal("expected error on duplicate registration")
	}
}

func TestRegistry_All_Preserves_Order(t *testing.T) {
	reg := NewRegistry()
	reg.MustRegister(newStub("C.001", policy.SeverityLow))
	reg.MustRegister(newStub("A.001", policy.SeverityHigh))
	reg.MustRegister(newStub("B.001", policy.SeverityMedium))

	all := reg.All()
	if len(all) != 3 {
		t.Fatalf("Len: got %d", len(all))
	}
	if all[0].Def().ID() != "C.001" || all[1].Def().ID() != "A.001" || all[2].Def().ID() != "B.001" {
		t.Errorf("order: got %s, %s, %s", all[0].Def().ID(), all[1].Def().ID(), all[2].Def().ID())
	}
}

func TestRegistry_Len(t *testing.T) {
	reg := NewRegistry()
	if reg.Len() != 0 {
		t.Errorf("empty: got %d", reg.Len())
	}
	reg.MustRegister(newStub("X.001", policy.SeverityLow))
	if reg.Len() != 1 {
		t.Errorf("after register: got %d", reg.Len())
	}
}

func TestRegistry_MustRegister_Panics_On_Duplicate(t *testing.T) {
	reg := NewRegistry()
	reg.MustRegister(newStub("X.001", policy.SeverityLow))

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on duplicate MustRegister")
		}
	}()
	reg.MustRegister(newStub("X.001", policy.SeverityLow))
}
