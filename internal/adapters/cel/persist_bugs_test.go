package cel

import (
	"encoding/binary"
	"testing"
)

// ---------------------------------------------------------------------------
// Bug 5 — decodeCache pre-sizes a slice from an untrusted uint64 count with no
// upper bound: make([]cachedEntry, 0, count). A corrupt/crafted count panics the
// runtime before any per-entry SHA integrity check runs.
//
// A count of 1<<62 trips Go's "makeslice: cap out of range" guard immediately
// (no real multi-exabyte allocation is attempted), so this test is safe to run.
//
// buildHeaderWithCount emits the REAL header (magic + version + cel-go version)
// that decodeCache validates before reaching the count, so the count guard — not
// an earlier "bad magic" rejection — is what's under test.
// ---------------------------------------------------------------------------
func TestDecodeCache_AbsurdEntryCount_ErrorsNotPanic(t *testing.T) {
	data := buildHeaderWithCount(1 << 62)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("decodeCache panicked on an absurd entry count (no cap guard before make): %v", r)
		}
	}()

	if _, err := decodeCache(data); err == nil {
		t.Fatal("decodeCache accepted a 2^62 entry count without bounding it against the buffer size")
	}
}

// ---------------------------------------------------------------------------
// Bug 4 — encodeCache writes the entry count up-front, then `continue`s mid-entry
// after the 32-byte SHA is already in the buffer (when an expression/proto exceeds
// uint32). The result on disk: the count claims N entries, but one entry is a bare
// SHA with no following length prefixes.
//
// The encoder path is latent (only fires for >4 GB expressions). This test
// reproduces the on-disk SHAPE the buggy encoder emits and asserts the decoder
// rejects it cleanly rather than silently misreading. Entry 1 is a fully-valid
// entry (empty CheckedExpr = zero-length proto) so the decoder reaches entry 2's
// bare SHA and fails THERE, which is the case under test.
// ---------------------------------------------------------------------------
func TestDecodeCache_TruncatedEntryAfterSHA_CleanError(t *testing.T) {
	data := buildHeaderWithCount(2) // count claims 2 entries

	// Entry 1: well-formed (empty proto is a valid, zero-length CheckedExpr).
	data = appendEntry(data, []byte("expr-one"), nil)
	// Entry 2: bare 32-byte SHA, no length prefixes follow (the buggy `continue` shape).
	var sha [32]byte
	data = append(data, sha[:]...)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("decodeCache panicked on a truncated entry instead of erroring: %v", r)
		}
	}()

	if _, err := decodeCache(data); err == nil {
		t.Fatal("decodeCache silently accepted a stream whose declared count exceeds the encoded entries")
	}
}

// ---------------------------------------------------------------------------
// Bug 6 — byteReader.readLengthPrefixed narrows a uint32 length via int(n). On
// 32-bit platforms (int == int32) any n in [2^31, 2^32) becomes NEGATIVE, the bound
// check `r.pos+int(n) > len(r.buf)` wrongly passes, and the slice expression panics.
//
// This reproduces ONLY on 32-bit. On amd64 (int == int64) it passes harmlessly.
// Run under a 32-bit build to exercise the panic:
//
//	GOARCH=386 go test -run TestByteReader_ReadLengthPrefixed_HighBitLength ./internal/adapters/cel/...
//
// ---------------------------------------------------------------------------
func TestByteReader_ReadLengthPrefixed_HighBitLength(t *testing.T) {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, 1<<31) // declares a 2 GiB payload; none follows

	r := &byteReader{buf: buf} // pos defaults to 0

	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("readLengthPrefixed panicked via int(uint32) narrowing (32-bit): %v", rec)
		}
	}()

	out, ok := r.readLengthPrefixed()
	if ok || out != nil {
		t.Fatalf("a 2 GiB length over an empty buffer must fail gracefully; got ok=%v len=%d", ok, len(out))
	}
}

// --- test helpers (match persist.go's real wire framing) -------------------

// buildHeaderWithCount writes the exact header decodeCache reads before the
// entries: magic, format version, cel-go version (length-prefixed), then the
// uint64 entry count. appendUint32/appendUint64 are persist.go's own helpers
// (same package), so the byte order matches the decoder by construction.
func buildHeaderWithCount(count uint64) []byte {
	var buf []byte
	buf = append(buf, cacheMagic...)
	buf = appendUint32(buf, cacheFormatVersion)
	cv := []byte(celGoVersion())
	buf = appendUint32(buf, uint32(len(cv)))
	buf = append(buf, cv...)
	buf = appendUint64(buf, count)
	return buf
}

// appendEntry writes one entry in persist.go's on-disk layout:
// [32-byte SHA][uint32 exprLen][expr][uint32 protoLen][proto].
func appendEntry(buf, expr, protoBytes []byte) []byte {
	var sha [32]byte
	buf = append(buf, sha[:]...)
	buf = appendUint32(buf, uint32(len(expr)))
	buf = append(buf, expr...)
	buf = appendUint32(buf, uint32(len(protoBytes)))
	buf = append(buf, protoBytes...)
	return buf
}
