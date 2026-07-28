package kernel

import (
	"testing"
)

func TestPrincipalRef_Validate_RejectsSpoofedSuffix(t *testing.T) {
	RegisterPrincipalSuffix("amazonaws.com")

	spoofed := PrincipalRef("attacker-evil-amazonaws.com")
	if err := spoofed.Validate(); err == nil {
		t.Error("CRITICAL BUG: Validate() accepted spoofed principal \"attacker-evil-amazonaws.com\"; must require exact match or dot-boundary prefix")
	}

	valid := PrincipalRef("s3.amazonaws.com")
	if err := valid.Validate(); err != nil {
		t.Errorf("expected valid service principal \"s3.amazonaws.com\" to pass, got err = %v", err)
	}
}
