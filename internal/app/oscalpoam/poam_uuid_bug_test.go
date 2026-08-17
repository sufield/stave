package oscalpoam

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/evaluation/remediation"
)

func TestGenerate_UUIDv5RFC4122Compliance(t *testing.T) {
	in := Input{
		Findings:   []remediation.Finding{},
		SystemUUID: "sys-01",
		EvalTime:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	poam := Generate(in)
	uuid := poam.UUID

	// According to RFC 4122:
	// - character at index 14 must be '5' (version 5)
	// - character at index 19 must be '8', '9', 'a', or 'b' (variant 10xx)
	if len(uuid) != 36 {
		t.Fatalf("expected 36-char UUID, got %q (len %d)", uuid, len(uuid))
	}

	if uuid[14] != '5' {
		t.Errorf("expected RFC 4122 version 5 UUID (char 14 = '5'), got %q in %q", string(uuid[14]), uuid)
	}

	variantChar := uuid[19]
	if variantChar != '8' && variantChar != '9' && variantChar != 'a' && variantChar != 'b' {
		t.Errorf("expected RFC 4122 variant (char 19 in [8,9,a,b]), got %q in %q", string(variantChar), uuid)
	}
}
