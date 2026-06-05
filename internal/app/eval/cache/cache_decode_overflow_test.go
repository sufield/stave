package cache

import (
	"testing"

	"github.com/sufield/stave/internal/core/evaluation"
)

// Bug 4: a crafted/corrupt cache header with keyLen or bodyLen >= 2^31
// must be rejected, not slipped past a wrapped-negative int() cast into a
// panicking slice (the failure mode on 32-bit builds). The uint64 bounds
// check makes the guard correct on every architecture.
func TestDecode_OversizedLengthsRejected(t *testing.T) {
	build := func(keyLen, bodyLen uint32) []byte {
		buf := []byte(cacheMagic)
		buf = appendUint32(buf, cacheFormatVersion)
		buf = appendUint32(buf, keyLen)
		// Intentionally do NOT provide keyLen bytes of key — the length
		// alone must be rejected before any slice happens.
		buf = appendUint32(buf, bodyLen)
		return buf
	}

	cases := map[string][]byte{
		"huge keyLen":  build(0xFFFFFFFF, 0),
		"2^31 keyLen":  build(1<<31, 0),
		"huge bodyLen": build(0, 0xFFFFFFFF),
	}

	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			var report evaluation.ComplianceReport
			// Must return ("", false) and must not panic.
			key, ok := decode(data, &report)
			if ok || key != "" {
				t.Fatalf("oversized length must be rejected, got key=%q ok=%v", key, ok)
			}
		})
	}
}

// Sanity: a well-formed buffer still round-trips, so the tightened guard
// did not reject legitimate input.
func TestDecode_ValidRoundTripStillWorks(t *testing.T) {
	data, err := encode("abc123", evaluation.ComplianceReport{})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var report evaluation.ComplianceReport
	key, ok := decode(data, &report)
	if !ok || key != "abc123" {
		t.Fatalf("valid buffer must decode, got key=%q ok=%v", key, ok)
	}
}
