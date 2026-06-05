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

// Each length guard in decode (min-length, post-version, post-key) must
// reject a buffer truncated at that exact point — returning ("", false)
// without ever reaching a binary.Uint32 read or a slice on bytes that
// are not there. A buffer one field short at each stage exercises the
// guard precisely; if the guard's arithmetic is wrong (e.g. len+4 → len-4)
// the read/slice panics instead of returning, so these cases pin the
// guards that a bare "huge length is rejected" test leaves unverified.
func TestDecode_TruncatedBuffersRejectedWithoutPanic(t *testing.T) {
	magic := []byte(cacheMagic)
	version := appendUint32(nil, cacheFormatVersion)

	cases := map[string][]byte{
		// Shorter than magic+4: the min-length guard (len < len(magic)+4).
		"one byte past magic": append(append([]byte{}, magic...), 0x01),
		"magic only":          append([]byte{}, magic...),
		// len >= 8 but < 12: passes min-length, fails the post-version
		// guard (pos+4 > len) before reading keyLen.
		"magic+version+2": append(append(append([]byte{}, magic...), version...), 0x01, 0x02),
		// magic+version+keyLen(=0) = 12 bytes: passes through keyLen but
		// has no room for bodyLen — the post-key guard must catch it
		// before reading bodyLen.
		"magic+version+zerokey": func() []byte {
			b := append(append([]byte{}, magic...), version...)
			return appendUint32(b, 0) // keyLen = 0, nothing after
		}(),
	}

	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			var report evaluation.ComplianceReport
			key, ok := decode(data, &report) // must not panic
			if ok || key != "" {
				t.Fatalf("truncated buffer must be rejected, got key=%q ok=%v", key, ok)
			}
		})
	}
}

// fitsUint32 must accept zero (an empty key or empty body is a legitimate
// length), so encode("") succeeds. This pins the lower bound of the guard
// (n >= 0), distinct from its rejection of negative/oversized lengths.
func TestEncode_EmptyKeyAccepted(t *testing.T) {
	data, err := encode("", evaluation.ComplianceReport{})
	if err != nil {
		t.Fatalf("empty key must encode (len 0 fits uint32), got error: %v", err)
	}
	var report evaluation.ComplianceReport
	key, ok := decode(data, &report)
	if !ok || key != "" {
		t.Fatalf("empty-key buffer must round-trip, got key=%q ok=%v", key, ok)
	}
}

func TestFitsUint32_AcceptsZero(t *testing.T) {
	if !fitsUint32(0) {
		t.Error("fitsUint32(0) must be true — zero is a valid length")
	}
}
