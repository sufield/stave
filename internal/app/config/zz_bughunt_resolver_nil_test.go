package config

import (
	"testing"
)

func TestBugHunt_Resolver_NilSafety(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ResolveAuditSetting panicked on nil resolver: %v", r)
		}
	}()

	var r *GovernanceResolver
	val, ok := ResolveAuditSetting(r, "max_unsafe")
	if !ok {
		t.Fatalf("expected ok=true for max_unsafe on nil resolver (should fallback to default)")
	}
	if val.Value != DefaultMaxUnsafeDuration {
		t.Errorf("expected default value %q, got %q", DefaultMaxUnsafeDuration, val.Value)
	}
}

func TestBugHunt_Resolver_QuietNilSafety(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("r.Quiet() panicked on nil resolver: %v", r)
		}
	}()

	var r *GovernanceResolver
	if got := r.Quiet(); got != false {
		t.Errorf("expected false, got %v", got)
	}
}
